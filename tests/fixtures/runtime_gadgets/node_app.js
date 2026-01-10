const http = require('http');
const https = require('https');

function sendTelemetry(config) {
  http.request({
    hostname: config.host,
    headers: config.headers,
    method: config.method || 'GET',
  });

  https.get({
    hostname: config.secureHost,
    path: config.path || '/',
    headers: config.secureHeaders,
  });

  fetch(config.url, { headers: config.fetchHeaders });
}

module.exports = { sendTelemetry };
