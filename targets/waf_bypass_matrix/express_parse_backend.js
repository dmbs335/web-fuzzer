/**
 * Express.js / busboy parse echo backend for WAF bypass finding validation.
 *
 * Uses busboy for multipart parsing (same underlying parser as many Node.js apps)
 * and body-parser for URL-encoded / JSON.
 *
 * Port: 19112
 */

'use strict';

const express = require('express');
const multer = require('multer');
const bodyParser = require('body-parser');

const app = express();
const PORT = parseInt(process.env.PORT || '3000', 10);

// Multer: store uploaded files in memory
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

// URL-encoded body parser (handles application/x-www-form-urlencoded)
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// JSON body parser
app.use(bodyParser.json({ type: ['application/json', 'text/json', 'application/x-json'], limit: '10mb' }));

// ── helpers ──────────────────────────────────────────────────────────────────

function flattenJson(obj, prefix, depth) {
  if (depth === undefined) depth = 6;
  if (depth <= 0) return {};
  const result = {};
  if (obj !== null && typeof obj === 'object' && !Array.isArray(obj)) {
    for (const [k, v] of Object.entries(obj)) {
      const key = prefix ? `${prefix}.${k}` : k;
      Object.assign(result, flattenJson(v, key, depth - 1));
    }
  } else if (Array.isArray(obj)) {
    obj.forEach((v, i) => {
      const key = prefix ? `${prefix}[${i}]` : `[${i}]`;
      Object.assign(result, flattenJson(v, key, depth - 1));
    });
  } else {
    const key = prefix || '_root';
    result[key] = [obj !== null && obj !== undefined ? String(obj) : ''];
  }
  return result;
}

function detectFormat(req) {
  const ct = (req.headers['content-type'] || '').toLowerCase();
  if (ct.startsWith('multipart/form-data')) return 'multipart';
  if (ct.startsWith('application/x-www-form-urlencoded')) return 'form';
  if (ct.includes('json')) return 'json';
  return 'unknown';
}

function buildResponse(req, fields, format, parseStatus, parseError) {
  const fieldCount = Object.keys(fields).length;
  const fieldNames = Object.keys(fields).slice(0, 20);

  const safeFields = {};
  for (const [k, vs] of Object.entries(fields)) {
    safeFields[k] = (Array.isArray(vs) ? vs : [vs]).map(v => String(v).slice(0, 500));
  }

  const body = {
    status: parseStatus,
    format: format,
    fields: safeFields,
    field_count: fieldCount,
  };
  if (parseError) body.error = parseError;

  const headers = {
    'Content-Type': 'application/json',
    'X-Backend-Reached': 'true',
    'X-Parse-Status': parseStatus,
    'X-Parse-Format': format,
    'X-Parsed-Field-Count': String(fieldCount),
    'X-Parsed-Field-Names': fieldNames.join(','),
  };
  if (parseError) {
    headers['X-Parse-Error'] = parseError.slice(0, 200);
  }

  // Per-field headers (first value, truncated)
  for (const name of fieldNames.slice(0, 10)) {
    const vs = fields[name];
    const val = Array.isArray(vs) ? vs[0] : vs;
    if (val !== undefined) {
      const safeName = name.slice(0, 30).replace(/[^\x20-\x7e]/g, '?');
      const safeVal = String(val).slice(0, 100).replace(/[\r\n]/g, ' ');
      headers[`X-Parsed-${safeName}`] = safeVal;
    }
  }

  return { headers, body };
}

// ── health ───────────────────────────────────────────────────────────────────

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// ── multipart route (must come before generic handler) ───────────────────────

app.all('/*splat', (req, res, next) => {
  const ct = req.headers['content-type'] || '';
  if (!ct.toLowerCase().startsWith('multipart/form-data')) {
    return next();
  }
  // Use multer to parse multipart
  upload.any()(req, res, (err) => {
    if (err) {
      const { headers, body } = buildResponse(req, {}, 'multipart', 'error', err.message);
      return res.status(200).set(headers).json(body);
    }
    const fields = {};
    // Body fields (text parts)
    for (const [k, v] of Object.entries(req.body || {})) {
      fields[k] = Array.isArray(v) ? v : [v];
    }
    // File parts (binary, read as latin-1)
    for (const f of (req.files || [])) {
      const val = f.buffer.toString('latin1').slice(0, 500);
      if (!fields[f.fieldname]) fields[f.fieldname] = [];
      fields[f.fieldname].push(val);
    }
    const { headers, body } = buildResponse(req, fields, 'multipart', 'ok', '');
    res.status(200).set(headers).json(body);
  });
});

// ── generic handler (form + JSON already parsed by body-parser middleware) ───

app.all('/*splat', (req, res) => {
  const fmt = detectFormat(req);
  let fields = {};
  let parseStatus = 'ok';
  let parseError = '';

  try {
    if (fmt === 'json') {
      if (req.body && typeof req.body === 'object') {
        fields = flattenJson(req.body, '', 6);
      } else {
        parseStatus = 'error';
        parseError = 'json body is null or non-object';
      }
    } else if (fmt === 'form') {
      for (const [k, v] of Object.entries(req.body || {})) {
        fields[k] = Array.isArray(v) ? v : [v];
      }
      if (Object.keys(fields).length === 0) {
        parseStatus = 'skip';
      }
    } else {
      parseStatus = 'skip';
    }
  } catch (e) {
    parseStatus = 'error';
    parseError = String(e).slice(0, 200);
  }

  const { headers, body } = buildResponse(req, fields, fmt, parseStatus, parseError);
  res.status(200).set(headers).json(body);
});

// ── start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Express parse backend listening on 0.0.0.0:${PORT}`);
});
