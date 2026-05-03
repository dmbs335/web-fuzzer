/**
 * Marker backend implemented in Node.js native http module.
 * Mirrors marker_backend.py response format but uses Node's llhttp parser.
 * This is the parser that has had many HRS CVEs (CVE-2022-32213, etc.)
 */
const http = require('http');
const crypto = require('crypto');

function responseFor(req, body) {
  const path = req.url || '/';
  const headers = req.headers;
  let status = 200;
  let marker = 'ok';
  let impact = 'none';
  let detail = 'generic';
  let routingSource = 'request-path';
  let cacheSource = 'request-path';
  let payload;

  if (path.startsWith('/__canary__/')) {
    payload = `BACKEND-MARKER canary ${path}`;
    status = 404;
    marker = 'canary';
    impact = 'canary';
    detail = path;
  } else if (path.startsWith('/early')) {
    payload = 'BACKEND-MARKER early';
    status = 401;
    marker = 'early';
    impact = 'acl_bypass';
    detail = 'early-gadget';
  } else if (path.startsWith('/cache/store')) {
    const cacheKey = headers['x-original-url'] || path;
    cacheSource = headers['x-original-url'] ? 'trailer' : 'header';
    payload = `BACKEND-MARKER cache IMPACT:cache_poison key=${cacheKey} source=${cacheSource}`;
    marker = 'cache';
    impact = 'cache_poison';
    detail = cacheKey;
  } else if (path.startsWith('/admin/panel')) {
    const hostValue = headers['host'] || 'backend-admin';
    routingSource = 'host';
    payload = `BACKEND-MARKER admin IMPACT:acl_bypass role=backend-admin host=${hostValue}`;
    status = 403;
    marker = 'admin';
    impact = 'acl_bypass';
    detail = hostValue;
  } else if (path.startsWith('/queue/append')) {
    routingSource = 'queue';
    payload = 'BACKEND-MARKER queue IMPACT:response_queue slot=primary';
    status = 202;
    marker = 'queue';
    impact = 'response_queue';
    detail = 'slot=primary';
  } else if (path.startsWith('/pipeline-victim-')) {
    // Pipeline victim probe - echo back the path so marker can be detected
    payload = `BACKEND-MARKER ok Backend saw: ${req.method} ${path} HTTP/1.1`;
    marker = 'ok';
  } else {
    payload = `BACKEND-MARKER ok ${body.slice(0, 32).toString('latin1')}`;
    marker = 'ok';
  }

  const effectiveKeys = ['host', 'x-forwarded-host', 'x-original-url',
                         'transfer-encoding', 'content-length'];
  const effectiveHeaders = effectiveKeys
    .filter(k => headers[k])
    .sort()
    .map(k => `${k}=${headers[k]}`)
    .join(';') || 'none';

  const bodyBoundary = `bytes=${body.length};chunked=${
    (headers['transfer-encoding'] || '').includes('chunked')
  };trailers=0`;

  const hashMaterial = `${req.method} ${path} HTTP/1.1|${effectiveHeaders}|${path}|${body.length}|`;
  const forwardedHash = crypto.createHash('sha1')
    .update(hashMaterial).digest('hex').slice(0, 20);

  return {
    status,
    headers: {
      'Content-Length': Buffer.byteLength(payload),
      'X-Backend-Marker': marker,
      'X-Impact-Marker': impact,
      'X-Impact-Detail': detail,
      'X-Forwarded-Request-Line': `${req.method} ${path} HTTP/1.1`,
      'X-Forwarded-Request-Hash': forwardedHash,
      'X-Effective-Headers': effectiveHeaders,
      'X-Body-Boundary': bodyBoundary,
      'X-Trailer-Forwarded': 'false',
      'X-Trailer-Merge': 'none',
      'X-Routing-Decision-Source': routingSource,
      'X-Cache-Decision-Source': cacheSource,
      'Connection': 'keep-alive',
    },
    body: payload,
  };
}

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', chunk => chunks.push(chunk));
  req.on('end', () => {
    const body = Buffer.concat(chunks);
    const r = responseFor(req, body);
    res.writeHead(r.status, r.headers);
    res.end(r.body);
  });
});

const port = parseInt(process.argv[2] || '8081', 10);
server.keepAliveTimeout = 30000;
server.listen(port, '0.0.0.0', () => {
  console.log(`Node.js marker backend on :${port}`);
});
