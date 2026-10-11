const allowlistConfig = require('./allowlist');
const allowedOrigins = Array.isArray(allowlistConfig) ? allowlistConfig : (allowlistConfig.origins || []);

const RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000;
const RATE_LIMIT_MAX = 1;
const requestBucket = new Map();

function normalizeOrigin(value) {
  if (!value) return null;

  const cleaned = String(value).split('#')[0].trim();
  if (!cleaned) return null;

  try {
    const url = new URL(cleaned);
    return { origin: url.origin, path: url.pathname.replace(/\/+$/, '') || '/' };
  } catch {
    return null;
  }
}

function isAllowedOrigin(requestUrl) {
  if (Array.isArray(allowlistConfig) ? false : Boolean(allowlistConfig.allowAllOrigins)) {
    return true;
  }

  const request = normalizeOrigin(requestUrl);
  if (!request) return false;
  return allowedOrigins.some((allowed) => {
    const configured = normalizeOrigin(allowed);
    if (!configured || configured.origin !== request.origin) return false;
    return configured.path === '/' || request.path === configured.path || request.path.startsWith(`${configured.path}/`);
  });
}

function setCorsHeaders(req, res) {
  const requestOrigin = req.headers.origin || req.headers.referer || '';
  const allowAllOrigins = !Array.isArray(allowlistConfig) && Boolean(allowlistConfig.allowAllOrigins);

  res.setHeader('Access-Control-Allow-Origin', allowAllOrigins ? '*' : 'null');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Origin, Content-Type, X-Requested-With, X-Frontend-Path');
  return { allowAllOrigins, requestOrigin };
}

function getClientKey(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const clientIp = forwarded ? String(forwarded).split(',')[0].trim() : (req.socket && req.socket.remoteAddress);
  return `${clientIp || 'unknown'}:${req.headers.origin || 'no-origin'}`;
}

function checkRateLimit(req) {
  const key = getClientKey(req);
  const now = Date.now();
  const bucket = requestBucket.get(key) || [];
  const fresh = bucket.filter((timestamp) => now - timestamp < RATE_LIMIT_WINDOW_MS);

  if (fresh.length >= RATE_LIMIT_MAX) {
    requestBucket.set(key, fresh);
    return false;
  }

  fresh.push(now);
  requestBucket.set(key, fresh);
  return true;
}

module.exports = async function handler(req, res) {
  const { allowAllOrigins, requestOrigin } = setCorsHeaders(req, res);

  const requestUrl = req.headers['x-frontend-path']
    ? `${requestOrigin}${req.headers['x-frontend-path']}`
    : requestOrigin;

  if (!allowAllOrigins && isAllowedOrigin(requestUrl)) {
    const normalizedOrigin = normalizeOrigin(requestOrigin);
    res.setHeader('Access-Control-Allow-Origin', normalizedOrigin ? normalizedOrigin.origin : 'null');
  }

  if (req.method === 'OPTIONS' && (allowAllOrigins || isAllowedOrigin(requestUrl))) {
    res.statusCode = 204;
    res.end();
    return;
  }

  if (!allowAllOrigins && !isAllowedOrigin(requestUrl)) {
    res.statusCode = 403;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: 'Access denied' }));
    return;
  }

  if (!allowAllOrigins) {
    const normalizedOrigin = normalizeOrigin(requestOrigin);
    res.setHeader('Access-Control-Allow-Origin', normalizedOrigin ? normalizedOrigin.origin : 'null');
  }
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Vary', 'Origin');

  if (req.method !== 'POST') {
    res.statusCode = 405;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: 'Method not allowed' }));
    return;
  }

  if (!checkRateLimit(req)) {
    res.statusCode = 429;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: 'Rate limit exceeded' }));
    return;
  }

  try {
    const body = await new Promise((resolve, reject) => {
      let data = '';
      req.on('data', (chunk) => {
        data += chunk;
        if (data.length > 16 * 1024) {
          reject(Object.assign(new Error('Request body too large'), { statusCode: 413 }));
          req.destroy();
        }
      });
      req.on('end', () => resolve(data));
      req.on('error', reject);
    });

    const payload = body ? JSON.parse(body) : {};

    const webhookUrl = 'https://discord.com/api/webhooks/1538356366970847262/FzN2ptJ9-GxASQP0v9gev0KrKbY7sFiHTbtoy_7i1s6sSgkjh9VJHdLGVXcJxmR1CNGb';

    const discordResponse = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        content: payload.content || 'Webhook triggered',
        username: payload.username || 'Vercel Webhook',
        avatar_url: payload.avatar_url || undefined
      })
    });

    if (!discordResponse.ok) {
      const errorText = await discordResponse.text();
      throw new Error(`Webhook failed: ${discordResponse.status} ${errorText}`);
    }

    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ ok: true }));
  } catch (error) {
    res.statusCode = error.statusCode || 500;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: error.statusCode === 413 ? 'Request body too large' : 'Webhook failed' }));
  }
};
