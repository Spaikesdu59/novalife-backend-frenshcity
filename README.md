# Backend Discord OAuth — NOVA-LIFE RP

Ce petit serveur gère uniquement la connexion Discord pour l'instant. Rien d'autre (pas de base de données, pas de lien avec le jeu) — ça viendra dans une étape suivante.

## 1. Créer l'application Discord

1. Va sur https://discord.com/developers/applications
2. Clique **New Application**, donne-lui un nom (ex: "NOVA-LIFE RP - Web")
3. Dans l'onglet **OAuth2** :
   - Note le **Client ID**
   - Clique **Reset Secret** pour générer et copier le **Client Secret**
   - Dans **Redirects**, ajoute exactement :
     `http://localhost:3000/auth/discord/callback` (pour tester en local)
     Tu ajouteras l'URL de production plus tard (ex: `https://api.tonserveur.com/auth/discord/callback`)

## 2. Configurer le backend

```bash
cd backend
cp .env.example .env
```

Ouvre `.env` et remplis `DISCORD_CLIENT_ID`, `DISCORD_CLIENT_SECRET`, et `JWT_SECRET` (n'importe quelle longue chaîne aléatoire).

## 3. Installer et lancer

```bash
npm install
npm start
```

Tu dois voir : `✅ Backend Discord OAuth lancé sur http://localhost:3000`

## 4. Tester le site en local

Le site (`index.html`, `compte.html`, etc.) doit être servi par un petit serveur local aussi (pas juste ouvert en double-clic), sinon les cookies de session ne fonctionnent pas bien. Le plus simple : l'extension **Live Server** sur VS Code, ou :

```bash
npx serve . -l 5500
```

Ouvre ensuite `http://localhost:5500/compte.html`, clique sur "Se connecter avec Discord", autorise l'accès — tu dois revenir sur le site avec ton pseudo et ton avatar Discord affichés.

## 5. Une fois que ça marche : mise en ligne

- Le backend doit tourner en continu quelque part (ton serveur hébergé, ou un service comme Render/Railway).
- Une fois hébergé avec une vraie URL (ex: `https://api.tonserveur.com`), mets à jour :
  - `.env` → `DISCORD_REDIRECT_URI` et `FRONTEND_URL` avec les bonnes URLs, et `NODE_ENV=production`
  - Discord Developer Portal → ajoute la nouvelle Redirect URL
  - `compte.html` → remplace `BACKEND_URL` par l'URL réelle du backend

## Ce que ce backend fait (et ne fait pas encore)

✅ Connexion/déconnexion Discord, session sécurisée (cookie signé, HttpOnly)
❌ Pas encore de lien avec un personnage en jeu — ça sera la prochaine étape une fois que la connexion Discord fonctionne bien
❌ Pas de base de données pour l'instant — rien n'est stocké côté serveur, tout est dans le cookie de session
