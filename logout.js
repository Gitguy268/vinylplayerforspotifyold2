/**
 * POST /api/auth/logout
 * Clears the encrypted token cookie, ending the Spotify session.
 */
const { clearTokenCookie } = require('../../lib/spotify');

module.exports = (req, res) => {
  res.setHeader('Set-Cookie', clearTokenCookie());
  return res.status(200).json({ ok: true });
};