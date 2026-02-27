// functions/_middleware.js
// Protects /dashboard.html and /api/cf/* routes

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  // Public routes
  if (
    path === '/' ||
    path === '/index.html' ||
    path === '/api/login' ||
    path.startsWith('/api/login')
  ) {
    return next();
  }

  // Protected routes need valid session
  const cookieHeader = request.headers.get('Cookie') || '';
  const token = getCookie(cookieHeader, 'session');

  if (!token) {
    if (path.startsWith('/api/')) {
      return json({ ok: false, error: 'Unauthorized' }, 401);
    }
    return Response.redirect(new URL('/', request.url), 302);
  }

  // Validate session
  let sessionValid = false;

  if (env.KV) {
    try {
      const data = await env.KV.get(`session:${token}`);
      if (data) {
        const session = JSON.parse(data);
        if (session.expiry > Date.now()) sessionValid = true;
      }
    } catch {}
  } else {
    // Fallback: trust cookie existence (less secure, but works without KV)
    // For production always use KV
    sessionValid = token.length === 64;
  }

  if (!sessionValid) {
    if (path.startsWith('/api/')) {
      return json({ ok: false, error: 'Session expired' }, 401);
    }
    return Response.redirect(new URL('/', request.url), 302);
  }

  return next();
}

function getCookie(header, name) {
  const match = header.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? match[1] : null;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}
