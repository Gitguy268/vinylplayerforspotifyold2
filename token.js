/**
 * GET /api/auth/token
 * Returns a valid access_token to the frontend.
 * Auto-refreshes the token if it has expired.
 * Tokens are read from the encrypted HTTP-only cookie.
 */
const {
  getTokensFromCookies,
  refreshAccessToken,
  makeTokenCookie,
} = require('../../lib/spotify');

module.exports = async (req, res) => {
  const tokens = getTokensFromCookies(req);

  if (!tokens || !tokens.access_token) {
    return res.status(401).json({
      error:   'not_authenticated',
      message: 'No Spotify session. Please log in.',
    });
  }

  /* ── Token still valid ─────────────────────── */
  if (Date.now() < tokens.expires_at) {
    return res.status(200).json({ access_token: tokens.access_token });
  }

  /* ── Token expired — try refreshing ────────── */
  if (!tokens.refresh_token) {
    return res.status(401).json({
      error:   'no_refresh_token',
      message: 'Session expired and no refresh token. Please log in again.',
    });
  }

  try {
    const newTokens = await refreshAccessToken(tokens.refresh_token);
    // Update the cookie with fresh tokens
    res.setHeader('Set-Cookie', makeTokenCookie(newTokens));
    return res.status(200).json({ access_token: newTokens.access_token });
  } catch (err) {
    console.error('Token refresh error:', err.message);
    return res.status(401).json({
      error:   'refresh_failed',
      message: 'Token refresh failed. Please log in again.',
    });
  }
};