# Mbata Agent — Deploy kwenye Render

## Kilichomo
- `server.js`, `db.js`, `mailer.js` — Backend (Node.js + Express + PostgreSQL)
- `public/index.html` — Frontend yako (nimeirekebisha bugs 2 za JavaScript zilizokuwa zinaizuia kufanya kazi)
- `render.yaml` — Blueprint ya kuweka Web Service + Database kwa pamoja kwenye Render
- `.env.example` — Mfano wa environment variables zinazohitajika

## Hatua za Deploy

### 1. Pakia code kwenye GitHub
Tengeneza repo mpya kwenye GitHub, kisha pakia folda hii yote (`mbata-agent`) ndani yake.

### 2. Fungua Render na anzisha Blueprint
1. Nenda [render.com](https://render.com) → **New** → **Blueprint**
2. Unganisha GitHub repo uliyotengeneza
3. Render itasoma `render.yaml` na kuandaa:
   - Web Service (`mbata-agent`)
   - PostgreSQL database (`mbata-agent-db`)
   - `DATABASE_URL` na `JWT_SECRET` zitajazwa automatic

### 3. Jaza SMTP variables (kwa ajili ya OTP emails)
Kwenye dashboard ya service, nenda **Environment** na jaza:
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`

Unaweza kutumia huduma kama **Brevo (Sendinblue)**, **Resend**, au **Gmail App Password**. Kama hutaweka hizi, OTP zitaandikwa kwenye **Logs** za Render badala ya kutumwa email (kwa ajili ya majaribio).

### 4. Deploy
Render itafanya `npm install` na `npm start` kiotomatiki. Database tables zitaundwa zenyewe wakati server inaanza (hakuna hatua ya ziada inayohitajika).

### 5. Fungua app
Baada ya deploy kukamilika, link kama `https://mbata-agent.onrender.com` itafanya kazi — register → thibitisha OTP → ingia → chagua profile (Finance/Business/Boss Connect/Education).

## Maelezo Muhimu
- **Plan ya bure ya Render** ina "sleep" baada ya muda wa kutokutumika — request ya kwanza baada ya kulala inaweza kuchukua sekunde 30-50.
- **Free PostgreSQL** ya Render inafutwa baada ya siku 90 kama huna plan ya kulipia — kumbuka ku-upgrade kabla ya hapo kwa matumizi ya kudumu.
- Boss Connect: kwa sasa mtu anapo-join kwa code, muunganisho unakuwa `active` moja kwa moja (hakuna hatua ya "boss approval" kwenye frontend uliyotoa).
