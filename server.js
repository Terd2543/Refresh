const express = require('express');
const cors    = require('cors');
const fs      = require('fs');
const path    = require('path');
const https   = require('https');

const app  = express();
const PORT = 3000;
const DATA_FILE = path.join(__dirname, 'data.json');

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname)); // serve index.html

// ─── Client ID registry (public/known client IDs) ───────────────────────────
const CLIENTS = {
  modrinth: {
    label:     'Modrinth',
    client_id: '00000000402b5328',   // Xbox Live / Modrinth launcher client id
    scope:     'service::user.auth.xboxlive.com::MBI_SSL',
  },
  microsoft: {
    label:     'Microsoft (official)',
    client_id: '00000000402b5328',
    scope:     'service::user.auth.xboxlive.com::MBI_SSL',
  },
};

// ─── Data store helpers ──────────────────────────────────────────────────────
function loadData() {
  if (!fs.existsSync(DATA_FILE)) return { tokens: [] };
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch { return { tokens: [] }; }
}

function saveData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

// ─── POST /api/refresh ───────────────────────────────────────────────────────
// Body: { refreshToken: string, client: 'modrinth' | 'microsoft' }
app.post('/api/refresh', async (req, res) => {
  const { refreshToken, client = 'modrinth' } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: 'refreshToken is required' });
  }

  const cfg = CLIENTS[client];
  if (!cfg) {
    return res.status(400).json({ error: `Unknown client: ${client}` });
  }

  console.log(`[${new Date().toISOString()}] Refreshing token — client: ${cfg.label}`);

  try {
    // ── Step 1: Exchange refresh token with Microsoft OAuth ──────────────────
    const msBody = new URLSearchParams({
      client_id:     cfg.client_id,
      grant_type:    'refresh_token',
      refresh_token: refreshToken,
      scope:         cfg.scope,
    }).toString();

    const msToken = await httpsPost(
      'login.live.com',
      '/oauth20_token.srf',
      { 'Content-Type': 'application/x-www-form-urlencoded' },
      msBody
    );

    if (msToken.error) {
      console.error('[MS OAuth] Error:', msToken.error, msToken.error_description);
      return res.status(401).json({
        error:   msToken.error,
        message: msToken.error_description || 'Microsoft OAuth failed',
      });
    }

    const newAccessToken  = msToken.access_token;
    const newRefreshToken = msToken.refresh_token;
    const expiresIn       = msToken.expires_in;

    console.log('[MS OAuth] Access token obtained ✓');

    // ── Step 2: Authenticate with Xbox Live ─────────────────────────────────
    const xblBody = JSON.stringify({
      Properties: {
        AuthMethod: 'RPS',
        SiteName:   'user.auth.xboxlive.com',
        RpsTicket:  `t=${newAccessToken}`,
      },
      RelyingParty: 'http://auth.xboxlive.com',
      TokenType:    'JWT',
    });

    const xblToken = await httpsPost(
      'user.auth.xboxlive.com',
      '/user/authenticate',
      { 'Content-Type': 'application/json', Accept: 'application/json' },
      xblBody
    );

    if (!xblToken.Token) {
      console.error('[XBL] Failed:', JSON.stringify(xblToken));
      return res.status(401).json({ error: 'Xbox Live authentication failed' });
    }

    const xblT   = xblToken.Token;
    const userHash = xblToken.DisplayClaims?.xui?.[0]?.uhs;
    console.log('[XBL] Token obtained ✓');

    // ── Step 3: Get XSTS token ───────────────────────────────────────────────
    const xstsBody = JSON.stringify({
      Properties: {
        SandboxId:  'RETAIL',
        UserTokens: [xblT],
      },
      RelyingParty: 'rp://api.minecraftservices.com/',
      TokenType:    'JWT',
    });

    const xstsToken = await httpsPost(
      'xsts.auth.xboxlive.com',
      '/xsts/authorize',
      { 'Content-Type': 'application/json', Accept: 'application/json' },
      xstsBody
    );

    if (!xstsToken.Token) {
      const xerr = xstsToken.XErr;
      let errMsg = 'XSTS authorization failed';
      if (xerr === 2148916233) errMsg = 'This account has no Xbox profile';
      if (xerr === 2148916238) errMsg = 'Child account — requires family settings';
      console.error('[XSTS] Failed XErr:', xerr);
      return res.status(401).json({ error: errMsg, xerr });
    }

    const xstsT = xstsToken.Token;
    console.log('[XSTS] Token obtained ✓');

    // ── Step 4: Get Minecraft access token ──────────────────────────────────
    const mcBody = JSON.stringify({
      identityToken: `XBL3.0 x=${userHash};${xstsT}`,
    });

    const mcToken = await httpsPost(
      'api.minecraftservices.com',
      '/authentication/login_with_xbox',
      { 'Content-Type': 'application/json', Accept: 'application/json' },
      mcBody
    );

    if (!mcToken.access_token) {
      console.error('[MC] Failed:', JSON.stringify(mcToken));
      return res.status(401).json({ error: 'Minecraft authentication failed' });
    }

    console.log('[MC] Minecraft access token obtained ✓');

    // ── Save to data.json ────────────────────────────────────────────────────
    const data = loadData();
    const entry = {
      id:               Date.now().toString(36),
      client,
      refreshToken:     newRefreshToken || refreshToken,
      accessToken:      mcToken.access_token,
      mcExpiresIn:      mcToken.expires_in,
      msExpiresIn:      expiresIn,
      savedAt:          new Date().toISOString(),
    };
    data.tokens.unshift(entry);
    saveData(data);
    console.log(`[SAVE] data.json now has ${data.tokens.length} entries`);

    return res.json({
      success:      true,
      accessToken:  mcToken.access_token,
      refreshToken: newRefreshToken || refreshToken,
      expiresIn:    mcToken.expires_in,
    });

  } catch (err) {
    console.error('[ERROR]', err.message);
    return res.status(500).json({ error: 'Internal server error', message: err.message });
  }
});

// ── GET /api/tokens ──────────────────────────────────────────────────────────
app.get('/api/tokens', (req, res) => {
  res.json(loadData());
});

// ── DELETE /api/tokens/:id ───────────────────────────────────────────────────
app.delete('/api/tokens/:id', (req, res) => {
  const data = loadData();
  data.tokens = data.tokens.filter(t => t.id !== req.params.id);
  saveData(data);
  res.json({ success: true });
});

// ─── HTTPS helper ────────────────────────────────────────────────────────────
function httpsPost(hostname, path, headers, body) {
  return new Promise((resolve, reject) => {
    const opts = {
      hostname, path, method: 'POST',
      headers: { ...headers, 'Content-Length': Buffer.byteLength(body) },
    };
    const req = https.request(opts, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => {
        try { resolve(JSON.parse(raw)); }
        catch { reject(new Error('Invalid JSON response from ' + hostname)); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ─── Start ───────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n  ⚡ MC Token Refresh Server`);
  console.log(`  → http://localhost:${PORT}\n`);
});
