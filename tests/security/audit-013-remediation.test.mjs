import test from 'node:test';
import assert from 'node:assert/strict';

import { createCredentialCacheOwner, CREDENTIAL_CACHE_STATES } from '../../services/security/credential-cache.js';
import { credentialSlotId } from '../../services/security/credential-store.js';

function effective(service, hash, ordinal = 1) {
  const slot = credentialSlotId(service);
  return {
    rowCount: ordinal,
    revoked: false,
    effectiveStore: {
      provenance_id: `p-${service}-${ordinal}`,
      service_name: service,
      agent_id: 'housekeeper',
      agent_valid_from: '2026-09-05T00:00:00.000Z',
      mutation_hash: Buffer.alloc(32, ordinal),
      body_json: { service, slot_id: slot, credential_hash: hash },
    },
  };
}

function fixture() {
  const entries = new Map([
    ['alpha', { slot: credentialSlotId('alpha'), value: 'alpha-secret-v1', hash: 'a'.repeat(64) }],
    ['beta', null],
  ]);
  const chains = new Map([
    [credentialSlotId('alpha'), effective('alpha', 'a'.repeat(64))],
    [credentialSlotId('beta'), { rowCount: 0, revoked: false, effectiveStore: null }],
  ]);
  const failures = new Set();
  let activeReads = 0;
  let peakReads = 0;
  const owner = createCredentialCacheOwner({
    services: ['alpha', 'beta'],
    readCredentialFn: async (service) => {
      activeReads += 1; peakReads = Math.max(peakReads, activeReads);
      try {
        if (failures.has(service)) throw new Error('transient_keychain_unavailable');
        return entries.get(service) || null;
      } finally { activeReads -= 1; }
    },
    readVerifiedSlotChainFn: async (slot) => {
      if (failures.has(slot)) throw new Error('transient_ledger_unavailable');
      return chains.get(slot);
    },
    logFn: { log() {} },
  });
  return { owner, entries, chains, failures, peakReads: () => peakReads };
}

test('initial boot publishes only a complete verified candidate', async () => {
  const f = fixture();
  await f.owner.load();
  assert.equal(f.owner.isLoaded(), true);
  assert.equal(f.owner.state('alpha').state, CREDENTIAL_CACHE_STATES.READY);
  assert.equal(f.owner.state('beta').state, CREDENTIAL_CACHE_STATES.ABSENT);
  assert.equal(f.owner.checkout('alpha').value, 'alpha-secret-v1');
  assert.equal(f.owner.checkout('beta'), null);
  assert(!JSON.stringify(f.owner.inspect()).includes('alpha-secret-v1'));

  const broken = fixture();
  broken.failures.add('alpha');
  await assert.rejects(broken.owner.load(), /initial_load_unavailable/);
  assert.equal(broken.owner.isLoaded(), false);
});

test('transient failure is explicit and cannot authorize retained bytes', async () => {
  const f = fixture();
  await f.owner.load();
  f.failures.add('alpha');
  await assert.rejects(f.owner.reload(), /reload_unavailable:alpha/);
  assert.equal(f.owner.state('alpha').state, CREDENTIAL_CACHE_STATES.UNAVAILABLE);
  assert.equal(f.owner.get('alpha'), null);
  assert.throws(() => f.owner.checkout('alpha'), /authority_unavailable/);
  assert.equal(f.owner.state('beta').state, CREDENTIAL_CACHE_STATES.ABSENT);

  f.failures.delete('alpha');
  f.entries.set('alpha', { slot: credentialSlotId('alpha'), value: 'alpha-secret-v2', hash: 'c'.repeat(64) });
  f.chains.set(credentialSlotId('alpha'), effective('alpha', 'c'.repeat(64), 2));
  const refresh = await f.owner.refresh('alpha');
  assert.equal(refresh.state, CREDENTIAL_CACHE_STATES.READY);
  assert.equal(f.owner.checkout('alpha').value, 'alpha-secret-v2');
});

test('signed revocation wins immediately and serialized reloads cannot restore an older version', async () => {
  const f = fixture();
  await f.owner.load();
  f.entries.set('alpha', null);
  f.chains.set(credentialSlotId('alpha'), { rowCount: 2, revoked: true, effectiveStore: null });
  const revoked = await f.owner.refresh('alpha');
  assert.equal(revoked.state, CREDENTIAL_CACHE_STATES.REVOKED);
  assert.equal(f.owner.checkout('alpha'), null);

  f.entries.set('alpha', { slot: credentialSlotId('alpha'), value: 'alpha-secret-v3', hash: 'd'.repeat(64) });
  f.chains.set(credentialSlotId('alpha'), effective('alpha', 'd'.repeat(64), 3));
  const first = f.owner.reload();
  const second = f.owner.reload();
  const [one, two] = await Promise.all([first, second]);
  assert(two.generation > one.generation);
  assert.equal(f.owner.checkout('alpha').credentialHash, 'd'.repeat(64));
});

test('initial load serializes refresh and cannot publish partial or overwrite a newer version', async () => {
  let releaseBoot;
  let markBootRead;
  const bootBlocked = new Promise((resolve) => { markBootRead = resolve; });
  const bootRelease = new Promise((resolve) => { releaseBoot = resolve; });
  let alphaReads = 0;
  let alphaChainReads = 0;
  let current = { slot: credentialSlotId('alpha'), value: 'alpha-v2', hash: 'c'.repeat(64) };
  const owner = createCredentialCacheOwner({
    services: ['alpha', 'beta'],
    readCredentialFn: async (service) => {
      if (service === 'beta') return null;
      alphaReads += 1;
      if (alphaReads === 1) {
        markBootRead();
        await bootRelease;
        return { slot: credentialSlotId('alpha'), value: 'alpha-v1', hash: 'a'.repeat(64) };
      }
      return current;
    },
    readVerifiedSlotChainFn: async (slot) => {
      if (slot === credentialSlotId('beta')) return { rowCount: 0, revoked: false, effectiveStore: null };
      alphaChainReads += 1;
      return alphaChainReads === 1
        ? effective('alpha', 'a'.repeat(64), 1)
        : effective('alpha', 'c'.repeat(64), 2);
    },
    logFn: { log() {} },
  });

  const load = owner.load();
  await bootBlocked;
  const refresh = owner.refresh('alpha');
  assert.equal(owner.isLoaded(), false);
  assert.throws(() => owner.state('beta'), /credential_cache_not_loaded/);
  releaseBoot();
  const [loaded, refreshed] = await Promise.all([load, refresh]);

  assert.equal(loaded.generation, 1);
  assert.equal(refreshed.generation, 2);
  assert.equal(owner.isLoaded(), true);
  assert.equal(owner.state('beta').state, CREDENTIAL_CACHE_STATES.ABSENT);
  assert.equal(owner.checkout('alpha').value, current.value);
  assert.equal(owner.checkout('alpha').credentialHash, current.hash);
});

for (const revokedBeforeReload of [true,false]) {
  test(`verified revocation fences a blocked multi-slot reload (before=${revokedBeforeReload})`, async () => {
    let revoked=false, hold=false, release, entered;
    const blocked=new Promise(resolve=>{entered=resolve;});
    const gate=new Promise(resolve=>{release=resolve;});
    const owner=createCredentialCacheOwner({services:['alpha','beta'],logFn:{log(){}},
      readCredentialFn:async service=>{
        if(service==='beta') {if(hold){entered();await gate;}return null;}
        if(revokedBeforeReload && revoked)throw new Error('keychain_unavailable');
        return {slot:credentialSlotId('alpha'),value:'retained',hash:'a'.repeat(64)};
      },
      readVerifiedSlotChainFn:async slot=>slot===credentialSlotId('beta')
        ? {rowCount:0,revoked:false,effectiveStore:null}
        : revoked ? {rowCount:2,revoked:true,effectiveStore:null}
          : effective('alpha','a'.repeat(64)),
    });
    await owner.load();
    if(revokedBeforeReload)revoked=true;
    hold=true;
    const reload=owner.reload();
    await blocked;
    await new Promise(resolve=>setImmediate(resolve));
    revoked=true;
    const refresh=owner.refresh('alpha');
    try {
      await new Promise(resolve=>setImmediate(resolve));
      assert.equal(owner.state('alpha').state,'REVOKED');
      assert.equal(owner.checkout('alpha'),null);
    } finally {release();}
    const [,refreshed]=await Promise.all([reload,refresh]);
    assert.equal(refreshed.state,'REVOKED');
    assert.equal(refreshed.entry,null);
    assert.equal(owner.checkout('alpha'),null);
  });
}
