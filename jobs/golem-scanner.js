/**
 * Golem Scanner - AI Agent Vulnerability Scanner
 * 
 * Autonomous bug bounty hunter for AI agent systems.
 * Scans targets for agent-specific vulnerabilities and saves findings to Aimos.
 * 
 * Usage: node golem-scanner.cjs --target <url> --class <vuln_class> --save
 */

import { AIMOS_COMPANY_ID } from '../services/core/runtime-config.js';
import http from 'http';
import https from 'https';
import { URL } from 'url';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

import { 
  getAllClasses, 
  getTestVectors, 
  getSuccessIndicators, 
  checkVulnerability,
  getSeverity,
  getBountyRange 
} from '../services/security/golem-vuln-classes.js';
import { persistMemory } from '../services/write/persist-memory.js';

// Configuration
const COMPANY_ID = AIMOS_COMPANY_ID;
const AGENT_ID = 'housekeeper';

// User-Agent rotation to avoid detection
const USER_AGENTS = [
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (Chrome/120.0.0.0)',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (Chrome/120.0.0.0)',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (Chrome/120.0.0.0)',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (Safari/605.1.15)'
];

/**
 * Make HTTP request to target
 */
async function makeRequest(url, payload, method = 'POST') {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const isHttps = parsedUrl.protocol === 'https:';
    const lib = isHttps ? https : http;
    
    const payloadStr = typeof payload === 'string' ? payload : JSON.stringify(payload);
    const userAgent = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
    
    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payloadStr),
        'User-Agent': userAgent,
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive'
      },
      timeout: 30000
    };

    const req = lib.request(options, (res) => {
      let data = '';
      res.setEncoding('utf8');
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: data,
          responseTime: Date.now()
        });
      });
    });

    req.on('error', (e) => {
      reject(new Error(`Request failed: ${e.message}`));
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout (30s)'));
    });

    req.write(payloadStr);
    req.end();
  });
}

/**
 * Test a single vulnerability vector against target
 */
async function testVector(targetUrl, vector, vulnClass) {
  const startTime = Date.now();
  
  try {
    const response = await makeRequest(targetUrl, { 
      message: vector.payload,
      conversation_id: `golem-scan-${Date.now()}-${vector.id}`,
      stream: false
    });
    
    const responseTime = Date.now() - startTime;
    const vulnCheck = checkVulnerability(vulnClass, response.body);
    
    return {
      vector_id: vector.id,
      vector_name: vector.name,
      payload: vector.payload,
      status_code: response.statusCode,
      response_time_ms: responseTime,
      response_preview: response.body.substring(0, 500),
      vulnerable: vulnCheck.vulnerable,
      confidence: vulnCheck.confidence,
      match_count: vulnCheck.matchCount,
      total_indicators: vulnCheck.totalIndicators,
      severity: getSeverity(vulnClass),
      bounty_range: getBountyRange(vulnClass)
    };
  } catch (error) {
    return {
      vector_id: vector.id,
      vector_name: vector.name,
      payload: vector.payload,
      error: error.message,
      status_code: null,
      response_time_ms: Date.now() - startTime,
      vulnerable: false,
      confidence: 0
    };
  }
}

/**
 * Scan target for a specific vulnerability class
 */
async function scanClass(targetUrl, vulnClass) {
  const vectors = getTestVectors(vulnClass);
  const results = [];
  let vulnerabilitiesFound = 0;
  
  console.log(`\n🔍 Scanning ${vulnClass} (${vectors.length} vectors)...`);
  
  for (const vector of vectors) {
    const result = await testVector(targetUrl, vector, vulnClass);
    results.push(result);
    
    if (result.vulnerable && result.confidence >= 0.6) {
      vulnerabilitiesFound++;
      console.log(`  ⚠️  VULNERABLE: ${result.vector_name} (confidence: ${(result.confidence * 100).toFixed(0)}%)`);
    } else {
      console.log(`  ✓ ${result.vector_name} - not vulnerable`);
    }
    
    // Rate limiting - avoid overwhelming target
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  
  return {
    vuln_class: vulnClass,
    total_vectors: vectors.length,
    vulnerabilities_found: vulnerabilitiesFound,
    results
  };
}

/**
 * Full scan across all vulnerability classes
 */
async function fullScan(targetUrl, specificClasses = null) {
  const classesToScan = specificClasses || getAllClasses();
  const scanResults = [];
  const totalStartTime = Date.now();
  
  console.log(`\n🛡️  GOLEM SCANNER - AI Agent Vulnerability Scan`);
  console.log(`Target: ${targetUrl}`);
  console.log(`Classes: ${classesToScan.join(', ')}`);
  console.log(`Started: ${new Date().toISOString()}`);
  console.log('='.repeat(60));
  
  for (const vulnClass of classesToScan) {
    const classResult = await scanClass(targetUrl, vulnClass);
    scanResults.push(classResult);
    
    // Brief pause between classes
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  
  const totalTime = Date.now() - totalStartTime;
  
  // Summary
  const totalVulns = scanResults.reduce((sum, r) => sum + r.vulnerabilities_found, 0);
  const totalVectors = scanResults.reduce((sum, r) => sum + r.total_vectors, 0);
  
  console.log('\n' + '='.repeat(60));
  console.log(`📊 SCAN COMPLETE`);
  console.log(`Total vectors tested: ${totalVectors}`);
  console.log(`Vulnerabilities found: ${totalVulns}`);
  console.log(`Scan duration: ${(totalTime / 1000).toFixed(1)}s`);
  console.log('='.repeat(60));
  
  return {
    target: targetUrl,
    scan_time: new Date().toISOString(),
    duration_ms: totalTime,
    total_vectors_tested: totalVectors,
    total_vulnerabilities: totalVulns,
    class_results: scanResults
  };
}

/**
 * Save findings to Aimos
 */
async function saveToAimos(scanResult) {
  const vulnerabilities = [];
  
  // Extract only vulnerable findings
  for (const classResult of scanResult.class_results) {
    for (const result of classResult.results) {
      if (result.vulnerable && result.confidence >= 0.6) {
        vulnerabilities.push({
          class: classResult.vuln_class,
          vector_id: result.vector_id,
          vector_name: result.vector_name,
          payload: result.payload,
          response_preview: result.response_preview,
          confidence: result.confidence,
          severity: result.severity,
          bounty_range: result.bounty_range
        });
      }
    }
  }
  
  if (vulnerabilities.length === 0) {
    console.log('ℹ️  No vulnerabilities to save');
    return null;
  }
  
  const memoryContent = {
    scan_id: `golem-${Date.now()}`,
    target: scanResult.target,
    scan_time: scanResult.scan_time,
    duration_ms: scanResult.duration_ms,
    total_vectors: scanResult.total_vectors_tested,
    vulnerabilities,
    summary: `Found ${vulnerabilities.length} potential vulnerabilities across ${scanResult.class_results.length} classes`
  };
  
  const saved = await persistMemory({
    company_id: COMPANY_ID,
    agent_id: AGENT_ID,
    key: memoryContent.scan_id,
    value: JSON.stringify(memoryContent),
    scope: 'system',
    clearance_level: 8,
    memory_type: 'security_finding',
    source: 'golem:manual-vulnerability-scan',
    mutation_authority: 'housekeeper',
  });
  if (saved?.rejected || !saved?.id) {
    throw new Error(`native_persistence_rejected:${saved?.reason || 'missing_memory_id'}`);
  }
  console.log(`✅ Saved to Aimos: ${vulnerabilities.length} vulnerabilities (memory ${saved.id})`);
  return saved;
}

/**
 * Generate PoC report for bounty submission
 */
function generatePoC(scanResult, vulnClass, vectorId) {
  const classResult = scanResult.class_results.find(r => r.vuln_class === vulnClass);
  if (!classResult) return null;
  
  const vectorResult = classResult.results.find(r => r.vector_id === vectorId);
  if (!vectorResult || !vectorResult.vulnerable) return null;
  
  const poc = {
    title: `${vulnClass} - ${vectorResult.vector_name}`,
    target: scanResult.target,
    severity: vectorResult.severity,
    bounty_range: vectorResult.bounty_range,
    confidence: vectorResult.confidence,
    reproduction_steps: [
      `1. Send POST request to ${scanResult.target}`,
      `2. Include payload: ${vectorResult.payload}`,
      `3. Observe response indicating vulnerability`,
      `4. Response preview: ${vectorResult.response_preview.substring(0, 200)}...`
    ],
    impact: `This vulnerability allows attackers to ${vectorResult.vector_name.toLowerCase()}. Potential impact includes data exfiltration, unauthorized access, or system compromise.`,
    remediation: 'Implement input validation, output encoding, and security guardrails for AI agent interactions.',
    evidence: {
      request_payload: vectorResult.payload,
      response_preview: vectorResult.response_preview,
      confidence_score: vectorResult.confidence,
      matched_indicators: vectorResult.match_count
    }
  };
  
  return poc;
}

/**
 * CLI entry point
 */
async function main() {
  const args = process.argv.slice(2);
  let target = null;
  let vulnClasses = null;
  let saveToAimosFlag = false;
  let generatePocFor = null;
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--target' && args[i + 1]) {
      target = args[++i];
    } else if (args[i] === '--class' && args[i + 1]) {
      vulnClasses = [args[++i]];
    } else if (args[i] === '--classes' && args[i + 1]) {
      vulnClasses = args[++i].split(',');
    } else if (args[i] === '--save') {
      saveToAimosFlag = true;
    } else if (args[i] === '--poc' && args[i + 1]) {
      generatePocFor = args[++i]; // format: vulnClass,vectorId
    } else if (args[i] === '--help') {
      console.log(`
Golem Scanner - AI Agent Vulnerability Scanner

Usage: node golem-scanner.js [options]

Options:
  --target <url>       Target URL to scan (required)
  --class <name>       Scan specific vulnerability class
  --classes <list>     Scan multiple classes (comma-separated)
  --save               Save findings to Aimos
  --poc <class,id>     Generate PoC for specific finding
  --help               Show this help

Vulnerability Classes:
  - prompt_injection
  - memory_poisoning
  - tool_abuse
  - agent_hijacking
  - token_exfiltration
  - rag_poisoning
  - context_overflow
  - sub_agent_abuse

Examples:
  node golem-scanner.js --target https://agent.example.com/chat
  node golem-scanner.js --target https://agent.example.com/chat --class prompt_injection --save
  node golem-scanner.js --target https://agent.example.com/chat --classes prompt_injection,memory_poisoning
`);
      process.exit(0);
    }
  }
  
  if (!target) {
    console.error('❌ Error: --target is required');
    console.error('Use --help for usage information');
    process.exit(1);
  }
  
  // Run scan
  const scanResult = await fullScan(target, vulnClasses);
  
  // Save to Aimos if requested
  if (saveToAimosFlag && scanResult.total_vulnerabilities > 0) {
    try {
      await saveToAimos(scanResult);
    } catch (error) {
      console.error(`❌ Aimos save failed: ${error.message}`);
    }
  }
  
  // Generate PoC if requested
  if (generatePocFor) {
    const [vulnClass, vectorId] = generatePocFor.split(',');
    const poc = generatePoC(scanResult, vulnClass, vectorId);
    
    if (poc) {
      console.log('\n📋 PoC Report:');
      console.log(JSON.stringify(poc, null, 2));
      
      // Save PoC to file
      const pocDir = path.join(path.dirname(__dirname), '..', 'pentest-reports', 'golem', 'findings');
      const pocFile = path.join(pocDir, `golem-${vulnClass}-${vectorId}-${Date.now()}.json`);
      
      try {
        fs.mkdirSync(pocDir, { recursive: true });
        fs.writeFileSync(pocFile, JSON.stringify(poc, null, 2));
        console.log(`\n✅ PoC saved to: ${pocFile}`);
      } catch (error) {
        console.error(`❌ Failed to save PoC: ${error.message}`);
      }
    }
  }
  
  // Return scan result for programmatic use
  return scanResult;
}

// Export for module use
export {
  fullScan,
  scanClass,
  testVector,
  makeRequest,
  saveToAimos,
  generatePoC,
  getAllClasses
};

// Run if called directly
if (process.argv[1] === __filename) {
  main().catch(console.error);
}
