
const express = require('express');
const cors = require('cors');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '16kb' }));
app.use(express.static(__dirname));

// Client configuration
const CLIENTS = {
  modrinth: {
    label: 'Modrinth',
    client_id: '00000000402b5328',
    scope: 'service::user.auth.xboxlive.com::MBI_SSL',
  },
  microsoft: {
    label: 'Microsoft',
    client_id: '00000000402b5328',
    scope: 'service::user.auth.xboxlive.com::MBI_SSL',
  },
};

// API status — no token storage
app.get('/api/tokens', (req, res) => {
  res.json({
    success: true,
    storage: false,
    message: 'Token storage is disabled',
    tokens: [],
  });
});

// Refresh token
app.post('/api/refresh', async (req, res) => {
  const { refreshToken, client = 'modrinth' } = req.body || {};

  if (
    typeof refreshToken !== 'string' ||
    !refreshToken.trim() ||
    refreshToken.length > 10000
  ) {
    return res.status(400).json({
      success: false,
      error: 'A valid refreshToken is required',
    });
  }

  const cfg = CLIENTS[client];

  if (!cfg) {
    return res.status(400).json({
      success: false,
      error: 'Unknown client',
    });
  }

  console.log(
    `[${new Date().toISOString()}] Refresh request: ${cfg.label}`
  );

  try {
    // STEP 1: Microsoft OAuth
    const msBody = new URLSearchParams({
      client_id: cfg.client_id,
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      scope: cfg.scope,
    }).toString();

    const msToken = await httpsPost(
      'login.live.com',
      '/oauth20_token.srf',
      {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      msBody
    );

    if (!msToken.access_token) {
      return res.status(401).json({
        success: false,
        error: msToken.error || 'Microsoft OAuth failed',
        message:
          msToken.error_description ||
          'Unable to refresh Microsoft token',
      });
    }

    const newAccessToken = msToken.access_token;
    const newRefreshToken = msToken.refresh_token || refreshToken;

    console.log('[Microsoft] OAuth completed');

    // STEP 2: Xbox Live authentication
    const xblBody = JSON.stringify({
      Properties: {
        AuthMethod: 'RPS',
        SiteName: 'user.auth.xboxlive.com',
        RpsTicket: `t=${newAccessToken}`,
      },
      RelyingParty: 'http://auth.xboxlive.com',
      TokenType: 'JWT',
    });

    const xblToken = await httpsPost(
      'user.auth.xboxlive.com',
      '/user/authenticate',
      {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      xblBody
    );

    if (!xblToken.Token) {
      return res.status(401).json({
        success: false,
        error: 'Xbox Live authentication failed',
      });
    }

    const xblT = xblToken.Token;
    const userHash = xblToken.DisplayClaims?.xui?.[0]?.uhs;

    if (!userHash) {
      return res.status(401).json({
        success: false,
        error: 'Xbox user hash was not returned',
      });
    }

    console.log('[Xbox Live] Authentication completed');

    // STEP 3: XSTS authorization
    const xstsBody = JSON.stringify({
      Properties: {
        SandboxId: 'RETAIL',
        UserTokens: [xblT],
      },
      RelyingParty: 'rp://api.minecraftservices.com/',
      TokenType: 'JWT',
    });

    const xstsToken = await httpsPost(
      'xsts.auth.xboxlive.com',
      '/xsts/authorize',
      {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      xstsBody
    );

    if (!xstsToken.Token) {
      let errorMessage = 'XSTS authorization failed';

      if (xstsToken.XErr === 2148916233) {
        errorMessage = 'This account has no Xbox profile';
      }

      if (xstsToken.XErr === 2148916238) {
        errorMessage = 'Child account requires family settings';
      }

      return res.status(401).json({
        success: false,
        error: errorMessage,
        xerr: xstsToken.XErr || null,
      });
    }

    const xstsT = xstsToken.Token;

    console.log('[XSTS] Authorization completed');

    // STEP 4: Minecraft authentication
    const mcBody = JSON.stringify({
      identityToken: `XBL3.0 x=${userHash};${xstsT}`,
    });

    const mcToken = await httpsPost(
      'api.minecraftservices.com',
      '/authentication/login_with_xbox',
      {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      mcBody
    );

    if (!mcToken.access_token) {
      return res.status(401).json({
        success: false,
        error: 'Minecraft authentication failed',
      });
    }

    console.log('[Minecraft] Authentication completed');

    // STEP 5: Return tokens without saving them
    return res.json({
      success: true,
      accessToken: mcToken.access_token,
      refreshToken: newRefreshToken,
      expiresIn: mcToken.expires_in,
      storage: false,
    });

  } catch (err) {
    // Never log token values or request bodies
    console.error('[ERROR]', err.message);

    return res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
});

// HTTPS POST helper
function httpsPost(hostname, requestPath, headers, body) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname,
      path: requestPath,
      method: 'POST',
      timeout: 15000,
      headers: {
        ...headers,
        'Content-Length': Buffer.byteLength(body),
      },
    };

    const request = https.request(options, (response) => {
      let raw = '';

      response.on('data', (chunk) => {
        raw += chunk;

        if (raw.length > 1024 * 1024) {
          request.destroy(new Error('Response too large'));
        }
      });

      response.on('end', () => {
        try {
          resolve(JSON.parse(raw));
        } catch {
          reject(
            new Error(`Invalid JSON response from ${hostname}`)
          );
        }
      });
    });

    request.on('timeout', () => {
      request.destroy(new Error('Request timed out'));
    });

    request.on('error', reject);

    request.write(body);
    request.end();
  });
}

// Start server
app.listen(PORT, () => {
  console.log('');
  console.log('  YUGI TOKEN REFRESH');
  console.log('  -------------------------');
  console.log(`  Server: http://localhost:${PORT}`);
  console.log('  Storage: DISABLED');
  console.log('  data.json: NOT USED');
  console.log('');
});
