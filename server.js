require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const {
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,
  JWT_SECRET,
  FRONTEND_URL,
  PORT = 3000
} = process.env;

// Vérification que tout est bien configuré avant de démarrer
const required = { DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_REDIRECT_URI, JWT_SECRET, FRONTEND_URL };
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

// ---------- Étape 1 : redirection vers Discord ----------
app.get('/auth/discord', (req, res) => {
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_REDIRECT_URI,
    response_type: 'code',
    scope: 'identify'
  });
  res.redirect(`https://discord.com/api/oauth2/authorize?${params.toString()}`);
});

// ---------- Étape 2 : Discord revient ici avec un code ----------
app.get('/auth/discord/callback', async (req, res) => {
  const { code, error } = req.query;

  if (error) return res.redirect(`${FRONTEND_URL}/compte.html?error=${error}`);
  if (!code) return res.redirect(`${FRONTEND_URL}/compte.html?error=missing_code`);

  try {
    // Échange du code contre un token d'accès Discord
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

    // Récupération du profil Discord du joueur
    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });

    if (!userRes.ok) throw new Error(`Récupération du profil échouée (${userRes.status})`);
    const discordUser = await userRes.json();

    // On crée notre propre session (JWT signé), on ne garde jamais le token Discord
    const sessionToken = jwt.sign(
      {
        id: discordUser.id,
        username: discordUser.username,
        avatar: discordUser.avatar
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.cookie('session', sessionToken, cookieOptions);
    res.redirect(`${FRONTEND_URL}/compte.html`);
  } catch (err) {
    console.error('Erreur OAuth Discord :', err.message);
    res.redirect(`${FRONTEND_URL}/compte.html?error=auth_failed`);
  }
});

// ---------- Étape 3 : le site demande "qui suis-je ?" ----------
app.get('/api/me', (req, res) => {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ connected: false });

  try {
    const user = jwt.verify(token, JWT_SECRET);
    const avatarUrl = user.avatar
      ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`
      : 'https://cdn.discordapp.com/embed/avatars/0.png';

    res.json({ connected: true, id: user.id, username: user.username, avatar: avatarUrl });
  } catch {
    res.status(401).json({ connected: false });
  }
});

// ---------- Déconnexion ----------
app.post('/auth/logout', (req, res) => {
  res.clearCookie('session', cookieOptions);
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`✅ Backend Discord OAuth lancé sur http://localhost:${PORT}`);
});
