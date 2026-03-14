// public/_worker.js
// Cloudflare Pages Worker — handles all API routes
// Static files (index.html, dashboard.html) are served automatically by Pages

const CF_BASE = 'https://api.cloudflare.com/client/v4';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // ── Static file passthrough ──────────────────────────────────────────
    // Let Pages serve HTML/CSS/JS files directly
    if (!path.startsWith('/api/')) {
      // Protect dashboard
      if (path === '/dashboard.html' || path === '/dashboard') {
        const ok = await validateSession(request, env);
        if (!ok) return Response.redirect(new URL('/', request.url), 302);
      }
      return env.ASSETS.fetch(request);
    }

    // ── API Router ───────────────────────────────────────────────────────
    const method = request.method;

    // Public
    if (path === '/api/login' && method === 'POST')  return handleLogin(request, env);
    if (path === '/api/logout' && method === 'POST') return handleLogout(request, env);

    // Protected — all /api/cf/* routes
    if (path.startsWith('/api/cf/')) {
      const ok = await validateSession(request, env);
      if (!ok) return json({ ok: false, error: 'Unauthorized' }, 401);

      if (path === '/api/cf/zone-info' && method === 'GET')        return handleZoneInfo(env);
      if (path === '/api/cf/rules'     && method === 'GET')        return handleListRules(env);
      if (path === '/api/cf/rules'     && method === 'POST')       return handleCreateRule(request, env);
      if (path.startsWith('/api/cf/rules/') && method === 'DELETE') {
        const id = path.split('/api/cf/rules/')[1];
        return handleDeleteRule(id, env);
      }
      if (path === '/api/cf/destinations' && method === 'GET')     return handleListDest(env);
      if (path === '/api/cf/destinations' && method === 'POST')    return handleCreateDest(request, env);
      if (path.startsWith('/api/cf/destinations/') && method === 'DELETE') {
        const id = path.split('/api/cf/destinations/')[1];
        return handleDeleteDest(id, env);
      }

      return json({ ok: false, error: 'Not found' }, 404);
    }

    return json({ ok: false, error: 'Not found' }, 404);
  }
};

// ════════════════════════════════════════════════════════════════════════
// AUTH
// ════════════════════════════════════════════════════════════════════════

async function handleLogin(request, env) {
  try {
    const { username, password } = await request.json();
    if (!username || !password) return json({ ok: false, error: 'Missing credentials' }, 400);

    const expectedUser = env.AUTH_USERNAME;
    const passwordHash = env.AUTH_PASSWORD_HASH;

    if (!expectedUser || !passwordHash) {
      return json({ ok: false, error: 'Server not configured. Set AUTH_USERNAME and AUTH_PASSWORD_HASH.' }, 500);
    }

    if (username.toLowerCase() !== expectedUser.toLowerCase()) {
      return json({ ok: false, error: 'Invalid credentials' }, 401);
    }

    const valid = await verifyPassword(password, passwordHash);
    if (!valid) return json({ ok: false, error: 'Invalid credentials' }, 401);

    const token = generateToken();
    const expiry = Date.now() + 24 * 60 * 60 * 1000;

    if (env.KV) {
      await env.KV.put(`session:${token}`, JSON.stringify({ username, expiry }), { expirationTtl: 86400 });
    }

    const res = json({ ok: true });
    res.headers.set('Set-Cookie',
      `session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400`
    );
    return res;
  } catch (e) {
    return json({ ok: false, error: 'Server error: ' + e.message }, 500);
  }
}

async function handleLogout(request, env) {
  const token = getCookie(request.headers.get('Cookie') || '', 'session');
  if (token && env.KV) await env.KV.delete(`session:${token}`).catch(() => {});
  const res = json({ ok: true });
  res.headers.set('Set-Cookie', 'session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0');
  return res;
}

async function validateSession(request, env) {
  const token = getCookie(request.headers.get('Cookie') || '', 'session');
  if (!token || token.length !== 64) return false;

  if (env.KV) {
    try {
      const data = await env.KV.get(`session:${token}`);
      if (!data) return false;
      const session = JSON.parse(data);
      return session.expiry > Date.now();
    } catch { return false; }
  }

  // Fallback without KV — trust token length
  return true;
}

// ════════════════════════════════════════════════════════════════════════
// CLOUDFLARE EMAIL ROUTING API
// ════════════════════════════════════════════════════════════════════════

async function handleZoneInfo(env) {
  const { CF_API_TOKEN, CF_ZONE_ID } = env;
  if (!CF_API_TOKEN || !CF_ZONE_ID) {
    return json({ zoneName: null, zoneId: null, needsSetup: true });
  }
  try {
    const res = await cfFetch(CF_API_TOKEN, `${CF_BASE}/zones/${CF_ZONE_ID}`);
    const data = await res.json();
    if (!data.success) return json({ ok: false, error: data.errors?.[0]?.message, needsSetup: true }, 400);
    return json({ zoneName: data.result.name, zoneId: CF_ZONE_ID, needsSetup: false });
  } catch (e) {
    return json({ ok: false, error: e.message, needsSetup: true }, 500);
  }
}

async function handleListRules(env) {
  const { CF_API_TOKEN, CF_ZONE_ID } = env;
  if (!CF_API_TOKEN || !CF_ZONE_ID) return json({ ok: false, error: 'CF_API_TOKEN and CF_ZONE_ID required' }, 503);
  const res = await cfFetch(CF_API_TOKEN, `${CF_BASE}/zones/${CF_ZONE_ID}/email/routing/rules`);
  const data = await res.json();
  if (!data.success) return json({ ok: false, error: data.errors?.[0]?.message }, 400);
  return json({ ok: true, rules: data.result || [] });
}

async function handleCreateRule(request, env) {
  const { CF_API_TOKEN, CF_ZONE_ID } = env;
  if (!CF_API_TOKEN || !CF_ZONE_ID) return json({ ok: false, error: 'CF_API_TOKEN and CF_ZONE_ID required' }, 503);
  const { from, to, type = 'literal' } = await request.json();
  if (!from || !to) return json({ ok: false, error: 'from and to are required' }, 400);

  const rule = {
    name: `Route ${from} → ${to}`,
    enabled: true,
    matchers: type === 'all' ? [{ type: 'all' }] : [{ type: 'literal', field: 'to', value: from }],
    actions: [{ type: 'forward', value: [to] }],
    priority: 1
  };

  const res = await cfFetch(CF_API_TOKEN, `${CF_BASE}/zones/${CF_ZONE_ID}/email/routing/rules`, {
    method: 'POST', body: JSON.stringify(rule)
  });
  const data = await res.json();
  if (!data.success) return json({ ok: false, error: data.errors?.[0]?.message }, 400);
  return json({ ok: true, rule: data.result });
}

async function handleDeleteRule(id, env) {
  const { CF_API_TOKEN, CF_ZONE_ID } = env;
  if (!CF_API_TOKEN || !CF_ZONE_ID) return json({ ok: false, error: 'Not configured' }, 503);
  const res = await cfFetch(CF_API_TOKEN, `${CF_BASE}/zones/${CF_ZONE_ID}/email/routing/rules/${id}`, { method: 'DELETE' });
  const data = await res.json();
  if (!data.success) return json({ ok: false, error: data.errors?.[0]?.message }, 400);
  return json({ ok: true });
}

async function handleListDest(env) {
  const { CF_API_TOKEN, CF_ACCOUNT_ID } = env;
  if (!CF_API_TOKEN || !CF_ACCOUNT_ID) return json({ ok: false, error: 'CF_API_TOKEN and CF_ACCOUNT_ID required' }, 503);
  const res = await cfFetch(CF_API_TOKEN, `${CF_BASE}/accounts/${CF_ACCOUNT_ID}/email/routing/addresses`);
  const data = await res.json();
  if (!data.success) return json({ ok: false, error: data.errors?.[0]?.message }, 400);
  return json({ ok: true, destinations: data.result || [] });
}

async function handleCreateDest(request, env) {
  const { CF_API_TOKEN, CF_ACCOUNT_ID } = env;
  if (!CF_API_TOKEN || !CF_ACCOUNT_ID) return json({ ok: false, error: 'CF_API_TOKEN and CF_ACCOUNT_ID required' }, 503);
  const { email } = await request.json();
  if (!email) return json({ ok: false, error: 'email required' }, 400);
  const res = await cfFetch(CF_API_TOKEN, `${CF_BASE}/accounts/${CF_ACCOUNT_ID}/email/routing/addresses`, {
    method: 'POST', body: JSON.stringify({ email })
  });
  const data = await res.json();
  if (!data.success) return json({ ok: false, error: data.errors?.[0]?.message }, 400);
  return json({ ok: true, destination: data.result });
}

async function handleDeleteDest(id, env) {
  const { CF_API_TOKEN, CF_ACCOUNT_ID } = env;
  if (!CF_API_TOKEN || !CF_ACCOUNT_ID) return json({ ok: false, error: 'Not configured' }, 503);
  const res = await cfFetch(CF_API_TOKEN, `${CF_BASE}/accounts/${CF_ACCOUNT_ID}/email/routing/addresses/${id}`, { method: 'DELETE' });
  const data = await res.json();
  if (!data.success) return json({ ok: false, error: data.errors?.[0]?.message }, 400);
  return json({ ok: true });
}

// ════════════════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════════════════

async function verifyPassword(password, hash) {
  if (hash.startsWith('sha256:')) {
    const parts = hash.split(':');
    if (parts.length !== 3) return false;
    const [, salt, expectedHex] = parts;
    const actual = await sha256Hex(salt + password);
    return timingSafeEqual(actual, expectedHex);
  }
  return false;
}

async function sha256Hex(str) {
  const buf = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return result === 0;
}

function generateToken() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function getCookie(header, name) {
  const match = header.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? match[1] : null;
}

function cfFetch(token, url, opts = {}) {
  return fetch(url, {
    ...opts,
    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', ...(opts.headers || {}) }
  });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}