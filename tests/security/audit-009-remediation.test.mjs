import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {performance} from 'node:perf_hooks';
import {setTimeout as delay} from 'node:timers/promises';
import {fetchWithTimeout} from '../../services/orchestration/http.js';

// Real transport peers only. They bind ephemeral loopback ports and are
// unconditionally stopped; these are fault measurements, not provider timing.
async function peer(t,handler) {
  let requests=0,closed=0;
  const server=http.createServer((req,res)=>{
    requests++;res.once('close',()=>closed++);handler(req,res,requests);
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));});
  return {url:`http://127.0.0.1:${server.address().port}`,requests:()=>requests,closed:()=>closed};
}
async function bounded(promise,watchdogMs=400) {
  let timer;
  try {return await Promise.race([promise,new Promise((_,reject)=>{
    timer=setTimeout(()=>reject(new Error('external_test_watchdog_expired')),watchdogMs);
  })]);}finally{clearTimeout(timer);}
}
const nativeAbort=error=>['AbortError','TimeoutError','RequestTimeoutError'].includes(error.name);

test('pre-aborted caller sends no HTTP request',async t=>{
  const p=await peer(t,(_req,res)=>res.end('must not arrive'));
  const reason=new Error('caller_cancelled_before_dispatch');
  await assert.rejects(fetchWithTimeout(p.url,{signal:AbortSignal.abort(reason),retry:false},100),error=>error===reason);
  assert.equal(p.requests(),0);
});

test('one deadline remains effective after headers and closes a stalled response',async t=>{
  const p=await peer(t,(_req,res)=>{res.writeHead(200);res.write('partial');});
  const start=performance.now();
  await assert.rejects(bounded((async()=>{const r=await fetchWithTimeout(p.url,{retry:false},60);await r.text();})()),nativeAbort);
  assert(performance.now()-start<250,'body consumption exceeded budget plus 190ms scheduling tolerance');
  await delay(30);assert.equal(p.closed(),1);
});

test('an endless body is cancelled at the same operation deadline',async t=>{
  const p=await peer(t,(_req,res)=>{
    res.writeHead(200);const timer=setInterval(()=>res.write('x'),5);res.once('close',()=>clearInterval(timer));
  });
  await assert.rejects(bounded((async()=>{const r=await fetchWithTimeout(p.url,{retry:false},60);await r.text();})()),nativeAbort);
  await delay(30);assert.equal(p.closed(),1);
});

test('caller cancellation remains connected during body consumption',async t=>{
  const p=await peer(t,(_req,res)=>{res.writeHead(200);res.write('partial');});
  const c=new AbortController();const response=await fetchWithTimeout(p.url,{signal:c.signal,retry:false},3000);
  const body=response.text();c.abort();
  await assert.rejects(bounded(body),nativeAbort);await delay(30);assert.equal(p.closed(),1);
});

test('retry backoff consumes the original budget and never resets it',async t=>{
  const p=await peer(t,req=>req.socket.destroy());const start=performance.now();
  await assert.rejects(bounded(fetchWithTimeout(p.url,{},60)),nativeAbort);
  assert(performance.now()-start<250);assert.equal(p.requests(),1);
});

test('consequential requests cannot opt into a blanket retry',async t=>{
  const p=await peer(t,req=>req.socket.destroy());
  await assert.rejects(bounded(fetchWithTimeout(p.url,{method:'POST',retry:true},60)),/http_retry_not_authorized/);
  assert.equal(p.requests(),0);
});

test('a successful safe retry retains the native Response and body',async t=>{
  const p=await peer(t,(req,res,n)=>{if(n===1)req.socket.destroy();else res.end('{"ok":true}');});
  const response=await fetchWithTimeout(p.url,{},1500);
  assert(response instanceof Response);assert.deepEqual(await response.json(),{ok:true});assert.equal(p.requests(),2);
});

test('malformed and dropped bodies reject instead of becoming successful empty results',async t=>{
  const p=await peer(t,(req,res)=>{if(req.url==='/json'){res.end('{broken');return;}res.writeHead(200,{'Content-Length':'100'});res.write('partial');setTimeout(()=>res.destroy(),5);});
  const malformed=await fetchWithTimeout(p.url+'/json',{retry:false},500);
  await assert.rejects(malformed.json(),SyntaxError);
  const dropped=await fetchWithTimeout(p.url+'/drop',{retry:false},500);
  await assert.rejects(dropped.text());assert.equal(p.requests(),2);
});
