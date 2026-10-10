const http = require('http');

const endpoints = [
  { path: '/api/health', expectStatus: [200] },
  { path: '/api/v1/plans', expectStatus: [200] },
  { path: '/', expectStatus: [200, 307, 308] },
  { path: '/pricing', expectStatus: [200] },
  { path: '/login', expectStatus: [200] },
  { path: '/checkout/success', expectStatus: [200] },
  { path: '/checkout/cancel', expectStatus: [200] },
  { path: '/dashboard/billing', expectStatus: [200, 307] },
  { path: '/dashboard/fleet', expectStatus: [200, 307] },
  { path: '/dashboard/threats', expectStatus: [200, 307] },
  { path: '/dashboard/compliance', expectStatus: [200, 307] },
];

async function checkEndpoint(ep) {
  return new Promise((resolve) => {
    const start = Date.now();
    const req = http.get('http://localhost:3000' + ep.path, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        const duration = Date.now() - start;
        const isOk = ep.expectStatus.includes(res.statusCode);
        const symbol = isOk ? '✅' : '❌';
        console.log(`${symbol} [${res.statusCode}] ${ep.path} (${duration}ms) - Length: ${data.length} bytes`);
        resolve({ path: ep.path, status: res.statusCode, ok: isOk });
      });
    });
    req.on('error', (err) => {
      console.error(`❌ [ERR] ${ep.path}: ${err.message}`);
      resolve({ path: ep.path, status: 0, ok: false, error: err.message });
    });
  });
}

(async () => {
  console.log('Testing ShieldDesk Application Endpoints on http://localhost:3000 ...\n');
  let pass = 0, fail = 0;
  for (const ep of endpoints) {
    const res = await checkEndpoint(ep);
    if (res.ok) pass++; else fail++;
  }
  console.log(`\n========================================`);
  console.log(`Result: ${pass} passed, ${fail} failed out of ${endpoints.length} endpoints.`);
  console.log(`========================================\n`);
  if (fail > 0) process.exit(1);
})();
