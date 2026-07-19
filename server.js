require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { RelyingParty } = require('openid');

const {
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,
  STEAM_API_KEY,
  PUBLIC_URL,
  JWT_SECRET,
  FRONTEND_URL,
  PLUGIN_API_URL,   // ex: https://xxxx.trycloudflare.com (tunnel) ou l'adresse définitive une fois hébergé
  PLUGIN_API_KEY,   // même clé que ApiKey dans webapi_config.json côté plugin
  PORT = 3000
} = process.env;

// Vérification que tout est bien configuré avant de démarrer
const required = { DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_REDIRECT_URI, STEAM_API_KEY, PUBLIC_URL, JWT_SECRET, FRONTEND_URL };
for (const [key, value] of Object.entries(required)) {
  if (!value) {
    console.error(`❌ Variable manquante dans .env : ${key}`);
    process.exit(1);
  }
}

const app = express();
app.use(cookieParser());
app.use(cors({
  origin: FRONTEND_URL,
  credentials: true
}));

const isProd = process.env.NODE_ENV === 'production';
const cookieOptions = {
  httpOnly: true,
  secure: isProd,                  // true en prod (HTTPS obligatoire), false en local (http)
  sameSite: isProd ? 'none' : 'lax',
  maxAge: 7 * 24 * 60 * 60 * 1000  // 7 jours
};

// Relying party OpenID pour Steam (vérifie l'identité directement auprès de Steam)
const steamRelyingParty = new RelyingParty(
  `${PUBLIC_URL}/auth/steam/callback`, // URL de retour après connexion Steam
  PUBLIC_URL,                          // Realm (domaine autorisé)
  true,                                // Vérification "stateless" (pas besoin de stocker de session côté serveur)
  false,                               // Mode strict désactivé
  []
);

function creerSessionToken(payload) {
  // ✅ CORRIGÉ : quand on fusionne une session existante (via ...sessionExistante)
  // avec de nouvelles infos, le payload décodé contient déjà "exp" (et "iat"),
  // ajoutés automatiquement par jwt.sign() la première fois. Réutiliser ce
  // payload tel quel avec { expiresIn } fait planter jsonwebtoken avec
  // l'erreur "Bad options.expiresIn option the payload already has an exp
  // property." — on retire donc ces 2 champs avant de re-signer.
  const { exp, iat, ...payloadPropre } = payload;
  return jwt.sign(payloadPropre, JWT_SECRET, { expiresIn: '7d' });
}

function lireSession(req) {
  const token = req.cookies.session;
  if (!token) return null;
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

// ================= DISCORD =================

// Étape 1 : redirection vers Discord
app.get('/auth/discord', (req, res) => {
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_REDIRECT_URI,
    response_type: 'code',
    scope: 'identify'
  });
  res.redirect(`https://discord.com/api/oauth2/authorize?${params.toString()}`);
});

// Étape 2 : Discord revient ici avec un code
app.get('/auth/discord/callback', async (req, res) => {
  const { code, error } = req.query;

  if (error) return res.redirect(`${FRONTEND_URL}/compte.html?error=${error}`);
  if (!code) return res.redirect(`${FRONTEND_URL}/compte.html?error=missing_code`);

  try {
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: DISCORD_REDIRECT_URI
      })
    });

    if (!tokenRes.ok) throw new Error(`Échange du token échoué (${tokenRes.status})`);
    const tokenData = await tokenRes.json();

    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });

    if (!userRes.ok) throw new Error(`Récupération du profil échouée (${userRes.status})`);
    const discordUser = await userRes.json();

    // On garde une éventuelle session Steam déjà présente en la fusionnant
    const sessionExistante = lireSession(req) || {};

    const sessionToken = creerSessionToken({
      ...sessionExistante,
      discordId: discordUser.id,
      discordUsername: discordUser.username,
      discordAvatar: discordUser.avatar
    });

    res.cookie('session', sessionToken, cookieOptions);
    res.redirect(`${FRONTEND_URL}/compte.html`);
  } catch (err) {
    console.error('Erreur OAuth Discord :', err.message);
    res.redirect(`${FRONTEND_URL}/compte.html?error=auth_failed`);
  }
});

// ================= STEAM =================

// Étape 1 : redirection vers Steam (nécessite d'être déjà connecté avec Discord)
app.get('/auth/steam', (req, res) => {
  const session = lireSession(req);
  if (!session || !session.discordId) {
    return res.redirect(`${FRONTEND_URL}/compte.html?error=discord_required`);
  }

  steamRelyingParty.authenticate('https://steamcommunity.com/openid', false, (error, authUrl) => {
    if (error || !authUrl) {
      console.error('Erreur init Steam :', error);
      return res.redirect(`${FRONTEND_URL}/compte.html?error=steam_init_failed`);
    }
    res.redirect(authUrl);
  });
});

// Étape 2 : Steam revient ici après connexion
app.get('/auth/steam/callback', (req, res) => {
  steamRelyingParty.verifyAssertion(req, async (error, result) => {
    if (error || !result || !result.authenticated) {
      console.error('Erreur vérification Steam :', error);
      return res.redirect(`${FRONTEND_URL}/compte.html?error=steam_failed`);
    }

    // L'identifiant Steam vérifié est à la fin de l'URL renvoyée par Steam
    const steamId = result.claimedIdentifier.split('/').pop();

    const sessionExistante = lireSession(req);
    if (!sessionExistante || !sessionExistante.discordId) {
      return res.redirect(`${FRONTEND_URL}/compte.html?error=discord_required`);
    }

    try {
      // Récupération du pseudo + avatar Steam via l'API publique Steam
      const steamRes = await fetch(
        `https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?key=${STEAM_API_KEY}&steamids=${steamId}`
      );
      const steamData = await steamRes.json();
      const profil = steamData?.response?.players?.[0];

      const sessionToken = creerSessionToken({
        ...sessionExistante,
        steamId,
        steamUsername: profil?.personaname || `Joueur ${steamId}`,
        steamAvatar: profil?.avatarfull || null
      });

      res.cookie('session', sessionToken, cookieOptions);
      res.redirect(`${FRONTEND_URL}/compte.html`);
    } catch (err) {
      console.error('Erreur récupération profil Steam :', err.message);
      res.redirect(`${FRONTEND_URL}/compte.html?error=steam_profile_failed`);
    }
  });
});

// ================= COMMUN =================

// Le site demande "qui suis-je ?"
app.get('/api/me', (req, res) => {
  const session = lireSession(req);
  if (!session || !session.discordId) return res.status(401).json({ connected: false });

  const discordAvatarUrl = session.discordAvatar
    ? `https://cdn.discordapp.com/avatars/${session.discordId}/${session.discordAvatar}.png`
    : 'https://cdn.discordapp.com/embed/avatars/0.png';

  res.json({
    connected: true,
    discord: {
      id: session.discordId,
      username: session.discordUsername,
      avatar: discordAvatarUrl
    },
    steam: session.steamId
      ? {
          id: session.steamId,
          username: session.steamUsername,
          avatar: session.steamAvatar
        }
      : null
  });
});

// Déconnexion (efface tout : Discord + Steam)
app.post('/auth/logout', (req, res) => {
  res.clearCookie('session', cookieOptions);
  res.json({ ok: true });
});

// ================= PERSONNAGES (plugin jeu) =================

// Le site demande "quels sont mes personnages en jeu ?"
// L'adresse du plugin (PLUGIN_API_URL) est configurable : un tunnel
// temporaire pendant les tests sur PC, puis l'adresse définitive une fois
// un vrai hébergeur en place — aucun changement de code nécessaire, juste
// la variable d'environnement à mettre à jour sur Render.
app.get('/api/characters', async (req, res) => {
  const session = lireSession(req);
  if (!session || !session.discordId) {
    return res.status(401).json({ error: 'not_connected' });
  }
  if (!session.steamId) {
    return res.status(400).json({ error: 'steam_not_linked' });
  }

  if (!PLUGIN_API_URL || !PLUGIN_API_KEY) {
    console.error('❌ PLUGIN_API_URL ou PLUGIN_API_KEY manquant dans les variables d\'environnement.');
    return res.status(503).json({ error: 'plugin_not_configured' });
  }

  try {
    // 🐛 DEBUG TEMPORAIRE : à retirer une fois le souci du statut 400 résolu
    console.log('DEBUG steamId envoyé au plugin :', JSON.stringify(session.steamId));

    const pluginRes = await fetch(
      `${PLUGIN_API_URL}/characters?steamid=${session.steamId}`,
      { headers: { 'X-Api-Key': PLUGIN_API_KEY } }
    );

    if (!pluginRes.ok) {
      console.error(`Erreur plugin jeu : statut ${pluginRes.status}`);
      return res.status(502).json({ error: 'plugin_unreachable' });
    }

    const data = await pluginRes.json();
    res.json(data);
  } catch (err) {
    // Le cas le plus courant : le serveur de jeu (ou le tunnel) est
    // simplement éteint/hors ligne en ce moment — pas une vraie erreur.
    console.error('Erreur contact plugin jeu :', err.message);
    res.status(503).json({ error: 'game_server_offline' });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Backend Discord + Steam lancé sur http://localhost:${PORT}`);
});
