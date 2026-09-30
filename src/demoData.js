// Shared presentation fixtures for the Sentry prototype. These are synthetic
// demo records and do not describe activity in a real production application.
export const DEMO_INCIDENT = {
  id: 'THR-2048',
  title: 'Simulated SQL injection probe',
  vector: 'SQL injection',
  method: 'POST',
  endpoint: '/api/query',
  sourceIp: '198.51.100.24',
  status: 'Blocked in demo telemetry',
  severity: 'CRITICAL',
  service: 'Sentry sample application · synthetic demo target',
  metrics: {
    requestsPerMinute: 1284,
    averageLatencyMs: 42,
    p95LatencyMs: 128,
    serviceHealthPercent: 99.98,
    baselineThreats: 7,
    baselineBlocked: 7,
    regionLabel: 'Synthetic application telemetry',
  },
  summary: 'A synthetic SQL injection probe was blocked in the Sentry demonstration. This is illustrative demo data, not a verified vulnerability in a real application.',
  forecast: 'Injection probes against data query surfaces',
  confidence: 78,
  evidence: [
    { name: 'request-capture.pcap', kind: 'Packet capture', size: '48 KB', hash: 'sha256: 8c19f4a2…e720', detail: 'Synthetic POST /api/query request with a SQL injection test string. Captured by the isolated demo replay.' },
    { name: 'attack-timeline.json', kind: 'Request trace', size: '12 KB', hash: 'sha256: 42bd7c81…a103', detail: 'Illustrative sequence of simulated ingress, isolated replay, and sandbox teardown events.' },
    { name: 'syscall-trace.log', kind: 'Syscall timeline', size: '31 KB', hash: 'sha256: 9f14d2cc…761e', detail: 'Synthetic process and network events from the demo sandbox. No production host activity is represented.' },
    { name: 'container-output.log', kind: 'Container output', size: '6 KB', hash: 'sha256: b761a5e0…083d', detail: 'Illustrative application output before the demo container exited.' },
  ],
};

export const BUSINESS_IMPACT = [
  ['MTTR', '< 2', 'MINUTES'],
  ['FALSE POSITIVES', '−85%', 'FEWER NOISY ALERTS'],
  ['PROD RISK', '0%', 'ISOLATED TESTING'],
  ['CLOUD COST', 'Fraction', 'OF STANDARD CI/CD'],
];
