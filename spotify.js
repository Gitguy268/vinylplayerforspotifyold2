/**
 * Shared Spotify helpers for Vercel serverless functions.
 *
 * Tokens are stored in encrypted HTTP-only cookies because Vercel
 * serverless functions are stateless — in-memory variables reset
 * on every cold start.
 *
 * Required Vercel Environment Variables:
 *   SPOTIFY_CLIENT_ID
 *   SPOTIFY_CLIENT_SECRET
 *   SPOTIFY_REDIRECT_URI   (e.g. https://your-app.vercel.app/api/auth/callback)
 *   COOKIE_SECRET           (any random 32+ char string)
 *   FRONTEND_URL            (e.g. https://your-app.vercel.app — optional, defaults to same origin)
 */

const crypto = require('crypto');

/* ── Config from environment ─────────────────── */
const CLIENT_ID     = process.env.SPOTIFY_CLIENT_ID     || '';
const CLIENT_SECRET = process.env.SPOTIFY_CLIENT_SECRET || '';
const REDIRECT_URI  = process.env.SPOTIFY_REDIRECT_URI  || '';
const FRONTEND_URL  = process.env.FRONTEND_URL          || '';
const COOKIE_SECRET = process.env.COOKIE_SECRET         || 'vinyl-player-change-this-secret-32ch';

/* ── Scopes needed for Web Playback SDK + API ── */
const SCOPES = [
  'streaming',
  'user-read-email',
  'user-read-private',
  'user-read-playback-state',
  'user-modify-playback-state',
  'user-read-currently-playing',
  'playlist-read-private',
  'playlist-read-collaborative',
  'user-library-read',
].join(' ');

/* ═══════════════════════════════════════════════ */
/*  AES-256-GCM encryption for cookie storage     */
/* ═══════════════════════════════════════════════ */

const ALGORITHM = 'aes-256-gcm';
const KEY = crypto.scryptSync(COOKIE_SECRET, 'vinyl-salt-2024', 32);

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);
  let enc = cipher.update(text, 'utf8', 'hex');
  enc += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return `${iv.toString('hex')}:${tag}:${enc}`;
}

function decrypt(data) {
  try {
    const parts = data.split(':');
    if (parts.length !== 3) return null;
    const [ivHex, tagHex, enc] = parts;
    const iv  = Buffer.from(ivHex, 'hex');
    const tag = Buffer.from(tagHex, 'hex');
    const decipher = crypto.createDecipheriv(ALGORITHM, KEY, iv);
    decipher.setAuthTag(tag);
    let dec = decipher.update(enc, 'hex', 'utf8');
    dec += decipher.final('utf8');
    return dec;
  } catch {
    return null;
  }
}

/* ═══════════════════════════════════════════════ */
/*  Cookie helpers                                 */
/* ═══════════════════════════════════════════════ */

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  cookieHeader.split(';').forEach(part => {
    const eq = part.indexOf('=');
    if (eq < 1) return;
    const key = part.substring(0, eq).trim();
    const val = part.substring(eq + 1).trim();
    cookies[key] = decodeURIComponent(val);
  });
  return cookies;
}

function getTokensFromCookies(req) {
  const cookies = parseCookies(req.headers.cookie);
  const raw = cookies['sp_tokens'];
  if (!raw) return null;
  const json = decrypt(raw);
  if (!json) return null;
  try {
    return JSON.parse(json);
  } catch {
    return null;
  }
}

function makeTokenCookie(tokens) {
  const payload = JSON.stringify(tokens);
  const encrypted = encrypt(payload);
  // All Vercel deployments (production + preview) use HTTPS
  return `sp_tokens=${encodeURIComponent(encrypted)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`;
}

function clearTokenCookie() {
  return 'sp_tokens=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0';
}

/* ═══════════════════════════════════════════════ */
/*  Spotify API: token exchange & refresh          */
/* ═══════════════════════════════════════════════ */

const AUTH_HEADER = 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');

async function exchangeCode(code) {
  const body = new URLSearchParams({
    grant_type:   'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
  });

  const res = await fetch('https://accounts.spotify.com/api/token', {
    method:  'POST',
    headers: {
      'Content-Type':  'application/x-www-form-urlencoded',
      'Authorization': AUTH_HEADER,
    },
    body: body.toString(),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Token exchange failed (${res.status}): ${text}`);
  }

  const data = await res.json();
  return {
    access_token:  data.access_token,
    refresh_token: data.refresh_token,
    expires_at:    Date.now() + data.expires_in * 1000 - 60000,
  };
}

async function refreshAccessToken(currentRefreshToken) {
  const body = new URLSearchParams({
    grant_type:    'refresh_token',
    refresh_token: currentRefreshToken,
  });

  const res = await fetch('https://accounts.spotify.com/api/token', {
    method:  'POST',
    headers: {
      'Content-Type':  'application/x-www-form-urlencoded',
      'Authorization': AUTH_HEADER,
    },
    body: body.toString(),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Token refresh failed (${res.status}): ${text}`);
  }

  const data = await res.json();
  return {
    access_token:  data.access_token,
    refresh_token: data.refresh_token || currentRefreshToken,
    expires_at:    Date.now() + data.expires_in * 1000 - 60000,
  };
}

module.exports = {
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URI,
  FRONTEND_URL,
  SCOPES,
  parseCookies,
  getTokensFromCookies,
  makeTokenCookie,
  clearTokenCookie,
  exchangeCode,
  refreshAccessToken,
};