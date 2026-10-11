const allowlistConfig = require('./allowlist');
const allowedOrigins = Array.isArray(allowlistConfig) ? allowlistConfig : (allowlistConfig.origins || []);
const fs = require('fs');
const path = require('path');

const JSON_PATH = path.join(__dirname, 'keys.json');

function normalizeOrigin(value) {
  if (!value) return null;

  const cleaned = String(value).split('#')[0].trim();
  if (!cleaned) return null;

  try {
    const url = new URL(cleaned);
    return url.origin;
  } catch {
    const withoutQuery = cleaned.replace(/[?#].*$/, '');
    return withoutQuery.replace(/\/+$/, '');
  }
}

function isAllowedOrigin(origin) {
  if (Array.isArray(allowlistConfig) ? false : Boolean(allowlistConfig.allowAllOrigins)) {
    return true;
  }

  if (!origin) return false;
  const normalizedOrigin = normalizeOrigin(origin);
  return allowedOrigins.some((allowed) => normalizeOrigin(allowed) === normalizedOrigin);
}

function setCorsHeaders(req, res) {
  const requestOrigin = normalizeOrigin(req.headers.origin || req.headers.referer || '');
  const allowAllOrigins = !Array.isArray(allowlistConfig) && Boolean(allowlistConfig.allowAllOrigins);

  res.setHeader('Access-Control-Allow-Origin', allowAllOrigins ? '*' : 'null');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Origin, Content-Type, X-Requested-With');
  return { allowAllOrigins, requestOrigin };
}

module.exports = async function handler(req, res) {
  const { allowAllOrigins, requestOrigin } = setCorsHeaders(req, res);

  if (!allowAllOrigins && isAllowedOrigin(requestOrigin)) {
    res.setHeader('Access-Control-Allow-Origin', requestOrigin);
  }

  if (req.method === 'OPTIONS' && (allowAllOrigins || isAllowedOrigin(requestOrigin))) {
    res.statusCode = 204;
    res.end();
    return;
  }

  if (!allowAllOrigins && !isAllowedOrigin(requestOrigin)) {
    res.statusCode = 403;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: 'Access denied' }));
    return;
  }

  if (!allowAllOrigins) res.setHeader('Access-Control-Allow-Origin', requestOrigin);

  try {
    const fileData = fs.readFileSync(JSON_PATH, 'utf8');
    const json = JSON.parse(fileData);

    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(json));
  } catch (error) {
    res.statusCode = 500;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: 'Unable to load keys data.' }));
  }
};
