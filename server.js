/**
 * Spotify OAuth Backend (Authorization Code Flow)
 *
 * Environment variables required (use a .env file):
 *   SPOTIFY_CLIENT_ID      – from Spotify Developer Dashboard
 *   SPOTIFY_CLIENT_SECRET   – from Spotify Developer Dashboard
 *   SPOTIFY_REDIRECT_URI    – must match Dashboard setting, e.g. http://localhost:3000/auth/callback
 *   FRONTEND_URL            – where to redirect after auth, e.g. http://localhost:3000
 *   PORT                    – server port (default 3000)
 *
 * Endpoints:
 *   GET  /auth/login     → redirects browser to Spotify authorization page
 *   GET  /auth/callback  → receives code from Spotify, exchanges for tokens, redirects to SPA
 *   GET  /auth/token     → returns a valid access_token (auto-refreshes if expired)
 *   POST /auth/logout    → clears stored tokens
 */

require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const CLIENT_ID     = process.env.SPOTIFY_CLIENT_ID;
const CLIENT_SECRET = process.env.SPOTIFY_CLIENT_SECRET;
const REDIRECT_URI  = process.env.SPOTIFY_REDIRECT_URI  || `http://localhost:${PORT}/auth/callback`;
const FRONTEND_URL  = process.env.FRONTEND_URL           || `http://localhost:${PORT}`;

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error('Missing SPOTIFY_CLIENT_ID or SPOTIFY_CLIENT_SECRET in environment.');
  process.exit(1);
}

/* ── In-memory token store (single-user; swap for DB/session in production) ── */
let tokenStore = {
  access_token:  null,
  refresh_token: null,
  expires_at:    0,       // epoch ms when access_token expires
  scope:         null,
};

/* ── PKCE helpers ─────────────────────────────────────────────────────────── */
// We use Authorization Code flow (not PKCE) because we have a backend that
// can safely hold the client_secret. PKCE is for public clients (no secret).
// Authorization Code with secret is the most secure server-side approach.

/* ── Scopes we request ────────────────────────────────────────────────────── */
const SCOPES = [
  'streaming',                     // Web Playback SDK
  'user-read-email',               // required by SDK
  'user-read-private',             // required by SDK
  'user-read-playback-state',      // read player state
  'user-modify-playback-state',    // control playback
  'user-read-currently-playing',   // current track info
  'playlist-read-private',         // read user playlists
  'playlist-read-collaborative',
  'user-library-read',             // liked songs
].join(' ');

/* ── Random state for CSRF protection ─────────────────────────────────────── */
let oauthState = null;

/* ── Serve the frontend HTML from the same origin ─────────────────────────── */
app.use(express.static(path.join(__dirname, 'public')));

/* ────────────────────────────────────────────────────────────────────────── */
/*  GET /auth/login                                                          */
/*  Redirects the user's browser to Spotify's authorization page.            */
/* ────────────────────────────────────────────────────────────────────────── */
app.get('/auth/login', (req, res) => {
  oauthState = crypto.randomBytes(16).toString('hex');

  const params = new URLSearchParams({
    response_type: 'code',
    client_id:     CLIENT_ID,
    scope:         SCOPES,
    redirect_uri:  REDIRECT_URI,
    state:         oauthState,
    show_dialog:   'false',
  });

  res.redirect(`https://accounts.spotify.com/authorize?${params.toString()}`);
});

/* ────────────────────────────────────────────────────────────────────────── */
/*  GET /auth/callback                                                       */
/*  Spotify redirects here after user grants/denies permission.              */
/*  We exchange the authorization code for access + refresh tokens.          */
/* ────────────────────────────────────────────────────────────────────────── */
app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    console.error('Spotify auth error:', error);
    return res.redirect(`${FRONTEND_URL}?spotify_error=${encodeURIComponent(error)}`);
  }

  // CSRF check
  if (state !== oauthState) {
    console.error('State mismatch – possible CSRF attack.');
    return res.redirect(`${FRONTEND_URL}?spotify_error=state_mismatch`);
  }

  try {
    const body = new URLSearchParams({
      grant_type:   'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
    });

    const resp = await fetch('https://accounts.spotify.com/api/token', {
      method: 'POST',
      headers: {
        'Content-Type':  'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64'),
      },
      body: body.toString(),
    });

    if (!resp.ok) {
      const text = await resp.text();
      console.error('Token exchange failed:', resp.status, text);
      return res.redirect(`${FRONTEND_URL}?spotify_error=token_exchange_failed`);
    }

    const data = await resp.json();

    tokenStore.access_token  = data.access_token;
    tokenStore.refresh_token = data.refresh_token;
    tokenStore.expires_at    = Date.now() + data.expires_in * 1000 - 60_000; // 1 min buffer
    tokenStore.scope         = data.scope;

    console.log('Spotify tokens acquired successfully.');
    // Redirect back to frontend with a flag so it knows auth succeeded
    res.redirect(`${FRONTEND_URL}?spotify_auth=ok`);

  } catch (err) {
    console.error('Token exchange exception:', err);
    res.redirect(`${FRONTEND_URL}?spotify_error=server_error`);
  }
});

/* ────────────────────────────────────────────────────────────────────────── */
/*  GET /auth/token                                                          */
/*  Returns a valid access_token. Refreshes automatically if expired.        */
/* ────────────────────────────────────────────────────────────────────────── */
app.get('/auth/token', async (req, res) => {
  if (!tokenStore.access_token) {
    return res.status(401).json({ error: 'not_authenticated', message: 'No Spotify session. Please log in.' });
  }

  // Auto-refresh if expired
  if (Date.now() >= tokenStore.expires_at && tokenStore.refresh_token) {
    console.log('Access token expired – refreshing…');
    try {
      const body = new URLSearchParams({
        grant_type:    'refresh_token',
        refresh_token: tokenStore.refresh_token,
      });

      const resp = await fetch('https://accounts.spotify.com/api/token', {
        method: 'POST',
        headers: {
          'Content-Type':  'application/x-www-form-urlencoded',
          'Authorization': 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64'),
        },
        body: body.toString(),
      });

      if (!resp.ok) {
        const text = await resp.text();
        console.error('Token refresh failed:', resp.status, text);
        // Clear tokens so user can re-auth
        tokenStore = { access_token: null, refresh_token: null, expires_at: 0, scope: null };
        return res.status(401).json({ error: 'refresh_failed', message: 'Token refresh failed. Please log in again.' });
      }

      const data = await resp.json();
      tokenStore.access_token = data.access_token;
      tokenStore.expires_at   = Date.now() + data.expires_in * 1000 - 60_000;
      // Spotify may or may not return a new refresh_token
      if (data.refresh_token) tokenStore.refresh_token = data.refresh_token;

      console.log('Token refreshed successfully.');
    } catch (err) {
      console.error('Token refresh exception:', err);
      return res.status(500).json({ error: 'server_error' });
    }
  }

  res.json({ access_token: tokenStore.access_token });
});

/* ────────────────────────────────────────────────────────────────────────── */
/*  POST /auth/logout                                                        */
/*  Clears stored tokens.                                                    */
/* ────────────────────────────────────────────────────────────────────────── */
app.post('/auth/logout', (_req, res) => {
  tokenStore = { access_token: null, refresh_token: null, expires_at: 0, scope: null };
  res.json({ ok: true });
});

/* ── Fallback: serve index.html for SPA routing ──────────────────────────── */
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🎵 Vinyl Record Player server running at http://localhost:${PORT}`);
  console.log(`   Spotify redirect URI: ${REDIRECT_URI}\n`);
});