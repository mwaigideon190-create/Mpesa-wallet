# Trade coin

Backend + web page in one app. The server serves the page, so open the server's address in a browser.

## Run locally (Node 18+)
    npm install
    npm start
Open http://localhost:3000. Accounts work immediately. Add money / Withdraw need the Daraja credentials:
copy `.env.example` to `.env`, fill it in, restart.

## Install on a phone
Open the deployed https address in Chrome, then tap **Install app** (or menu > Add to Home screen). It opens full-screen like an app. Needs HTTPS.

## Deploy
- Render: push this folder to GitHub, then New > Blueprint (uses render.yaml). Add the Daraja keys in the dashboard.
- Docker: `docker build -t wallet . && docker run -p 3000:3000 --env-file .env wallet`
- The database is the file `wallet.db`. Put it on a persistent disk, or move to Postgres for production.

## Daraja callbacks
Set CALLBACK_BASE_URL to the public https address (on Render it is picked up automatically).
Locally, use `ngrok http 3000` and set CALLBACK_BASE_URL to the ngrok address.

## Endpoints
GET /health · GET /health/mpesa (tests your Daraja keys via the OAuth token URL) · POST /auth/register {email, password, phone} · POST /auth/login
GET /wallet · GET /wallet/transactions
POST /wallet/topup {amount} (STK Push) · POST /wallet/withdraw {amount, password} (B2C)

## Before go-live
- Test in the sandbox, then set MPESA_ENV=production with the approved shortcode and production credentials.
- SECURITY_CREDENTIAL = initiator password encrypted with Safaricom's certificate.
- Whitelist Safaricom's callback IPs, serve over HTTPS only, keep secrets out of the repo.
- Reconcile daily against the M-Pesa statement; handle B2C timeouts with the Transaction Status API.
- Get an independent security review before real funds flow.

## Site editor (Admin > Site)
1. Keep `site-config.js` next to `server.js`. In `server.js`, after `express.json()` is set up, add: `require('./site-config')(app);`
2. Files to serve: index.html, admin.html, layouts.css, site.js, sw.js, both manifests, and all png icons.
3. Link: on Render, Settings > Custom Domains > add tradecoin.com (you must own the domain), then add the DNS records Render shows.
