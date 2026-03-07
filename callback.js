/**
 * GET /api/auth/callback
 * Spotify redirects here after user grants/denies permission.
 * Exchanges the authorization code for tokens, stores them in an
 * encrypted cookie, then redirects back to the SPA.
 */
const {
  FRONTEND_URL,
  parseCookies,
  exchangeCode,
  makeTokenCookie,
} = require('../../lib/spotify');

module.exports = async (req, res) => {
  // Vercel provides parsed query params on req.query
  const code  = req.query.code   || '';
  const state = req.query.state  || '';
  const error = req.query.error  || '';

  const redirectBase = FRONTEND_URL || '/';

  /* ── User denied access ────────────────────── */
  if (error) {
    res.setHeader('Location', `${redirectBase}?spotify_error=${encodeURIComponent(error)}`);
    return res.status(302).end();
  }

  /* ── CSRF check: compare state to cookie ───── */
  const cookies = parseCookies(req.headers.cookie);
  if (!state || state !== cookies['sp_state']) {
    res.setHeader('Location', `${redirectBase}?spotify_error=state_mismatch`);
    return res.status(302).end();
  }

  /* ── Exchange code for tokens ──────────────── */
  try {
    const tokens = await exchangeCode(code);

    // Set encrypted token cookie + clear the state cookie
    res.setHeader('Set-Cookie', [
      makeTokenCookie(tokens),
      'sp_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0',
    ]);

    res.setHeader('Location', `${redirectBase}?spotify_auth=ok`);
    return res.status(302).end();
  } catch (err) {
    console.error('Callback token exchange error:', err.message);
    res.setHeader('Location', `${redirectBase}?spotify_error=token_exchange_failed`);
    return res.status(302).end();
  }
};