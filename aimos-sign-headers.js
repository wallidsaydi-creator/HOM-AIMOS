#!/usr/bin/env node
// Usage: aimos-sign-headers.js --agent-id <agent_id> [--body -] [--method <M>] [--path <P>]
//        Reads JSON body from stdin when --body - is passed (else signs empty {}).
//        No env fallback for agent_id or privkey path — env-based identity bypasses the cert envelope.
// R1 Step 2: header construction delegated to the single shared
// buildEnvelopeHeaders(agentId, method, path, body) helper. --method/--path
// are folded into the signature only once OUTBOUND_SIG_FORM flips to 2; they
// are always advertised via the X-Aimos-Sig-Form header.
import fs from 'node:fs';
import { buildEnvelopeHeaders } from './services/security/envelope-headers.js';

function readStdin() {
  return fs.readFileSync(0, 'utf8');
}

function parseArgs(argv) {
  const args = { bodyFromStdin: false, bodyInline: null, agentId: null, method: 'POST', path: '/aimos/save', execUrl: null };
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i] === '--body' && argv[i + 1] === '-') {
      args.bodyFromStdin = true;
      i += 1;
    } else if (argv[i] === '--agent-id' && argv[i + 1]) {
      args.agentId = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--agent' && argv[i + 1]) {
      args.agentId = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--body' && argv[i + 1]) {
      args.bodyInline = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--method' && argv[i + 1]) {
      args.method = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--path' && argv[i + 1]) {
      args.path = argv[i + 1];
      i += 1;
    } else if (argv[i] === '--exec' && argv[i + 1]) {
      args.execUrl = argv[i + 1];
      i += 1;
    }
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv);
  if (!args.agentId) {
    console.error('Usage: aimos-sign-headers.js --agent-id <agent_id> [--body -]');
    console.error('       Enroll an agent via scripts/identity/enroll-agent.js and pass its ID.');
    console.error('       No env default — env-based agent_id bypasses the cert envelope.');
    process.exit(64);
  }
  const bodyText = args.bodyFromStdin ? readStdin() : (args.bodyInline || '{}');
  let body;
  try {
    body = bodyText.trim() ? JSON.parse(bodyText) : {};
  } catch (error) {
    console.error(`aimos-sign-headers: invalid JSON body: ${error.message}`);
    process.exit(2);
  }

  const headers = await buildEnvelopeHeaders(args.agentId, args.method, args.path, body);
  if (!args.execUrl) {
    console.log(JSON.stringify(headers));
    return;
  }

  const method = String(args.method || 'GET').toUpperCase();
  const response = await fetch(args.execUrl, {
    method,
    headers: { ...headers, 'Content-Type': 'application/json' },
    ...(method === 'GET' || method === 'HEAD' ? {} : { body: JSON.stringify(body) })
  });
  const responseText = await response.text();
  process.stdout.write(responseText);
  if (!response.ok) process.exitCode = 1;
}

main().catch((error) => {
  console.error(`aimos-sign-headers: ${error && error.stack ? error.stack : error}`);
  process.exit(1);
});
