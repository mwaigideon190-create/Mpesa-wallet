# M-Pesa Wallet (Daraja)

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
GET /game/state · POST /game/bet {stake, confirm18, chance_pct} · GET /game/demo-config
Admin: GET /admin/treasury (includes coin value history) · POST /admin/treasury/send · POST /admin/treasury/fund · GET/POST /admin/demo

## Before go-live
- Test in the sandbox, then set MPESA_ENV=production with the approved shortcode and production credentials.
- SECURITY_CREDENTIAL = initiator password encrypted with Safaricom's certificate.
- Whitelist Safaricom's callback IPs, serve over HTTPS only, keep secrets out of the repo.
- Reconcile daily against the M-Pesa statement; handle B2C timeouts with the Transaction Status API.
- Get an independent security review before real funds flow.

## Tradecoin game and practice mode
- Real game: a game of chance. The win chance is GAME_WIN_PCT_LOW (5%) until the Treasury reaches GAME_TARGET_USD ($150), then GAME_WIN_PCT_HIGH (29%). Fee, round time, stake limits and the daily loss limit are the other GAME_* settings (see render.yaml). The win chance is shown to every client before they bet.
- The chart shows the real Treasury balance (the coin value), recorded every few seconds in `game_ticks`. It is a display and does not change any result.
- Practice mode: fake money that runs only in the client's browser. The admin page has a Practice tab (on/off, win chances, target, starting balance, reset). Practice never touches wallets or the Treasury.
- Put `index.html`, `admin.html`, `sw.js`, `manifest.webmanifest`, `icon-192.png`, `icon-512.png` and the legal pages (`terms.html`, `privacy.html`, `risk-disclosure.html`, `refund-policy.html`) in the `public/` folder; the server serves that folder.
