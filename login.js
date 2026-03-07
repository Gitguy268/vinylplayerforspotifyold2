/**
 * GET /api/auth/login
 * Redirects the browser to Spotify's authorization consent page.
 * Stores a random CSRF state in a short-lived cookie.
 */
const crypto = require('crypto');
const { CLIENT_ID, REDIRECT_URI, SCOPES } = require('../../lib/spotify');

module.exports = (req, res) => {
  if (!CLIENT_ID || !REDIRECT_URI) {
    return res.status(500).json({
      error: 'server_misconfigured',
      message: 'SPOTIFY_CLIENT_ID or SPOTIFY_REDIRECT_URI not set.',
    });
  }

  const state = crypto.randomBytes(16).toString('hex');

  const params = new URLSearchParams({
    response_type: 'code',
    client_id:     CLIENT_ID,
    scope:         SCOPES,
    redirect_uri:  REDIRECT_URI,
    state,
    show_dialog:   'false',
  });

  const spotifyUrl = `https://accounts.spotify.com/authorize?${params.toString()}`;

  // Store state in a short-lived HttpOnly cookie for CSRF verification in callback
  res.setHeader('Set-Cookie', `sp_state=${state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`);
  res.setHeader('Location', spotifyUrl);
  res.status(302).end();
};