# Reward Token System (Free Food / Gift)

Generates a barcode token for a customer's free food or gift. The customer
shows the token at **any outlet**, and the admin there scans it to find out
whether it is:

| Result | Meaning |
|---|---|
| ✅ **VALID** | Genuine and unused. The admin presses **Mark as claimed & give reward**. |
| ⚠️ **ALREADY CLAIMED** | Already used. Shows when and at which outlet. |
| ❌ **FAKE** | Wrong format, wrong security signature, or not in the system. |
| ⌛ **EXPIRED** | Past its validity date. |
| 🚫 **CANCELLED** | An admin cancelled it on the *All Tokens* page. |

## Run it

```bash
pip install -r requirements.txt
ADMIN_PASSWORD=yourStrongPassword python3 app.py
```

Open http://localhost:5000 and log in with the outlet name and the admin password.

## How to use

1. **Generate Token**: pick *Free Food* or *Gift*, enter the item, and optionally the customer
   name and phone, the validity in days and how many tokens to make. You get a
   ticket with a barcode, a QR code, or both (switch any time on the ticket). Print it, or let the customer take a photo of it.
2. **Admin: Scan & Verify**: at the outlet, scan the customer's barcode in one of three ways:
   - **Camera** (phone, tablet or laptop webcam): press *Start camera*
   - **USB/Bluetooth barcode scanner**: click the input box and scan (it types the code and presses Enter)
   - **Type** the code printed under the barcode
3. **All Tokens**: search tokens, see their status, reprint tickets, cancel tokens, and see how many fake scans were caught.

## How fake tokens are detected

Codes look like `RW-7K3M9QX2-A1B2C3`: an 8-character random ID plus a
6-character **HMAC-SHA256 signature** made with a secret key (`.secret_key`,
created automatically on the first run). A code someone makes up or edits fails
the signature check. A code must also exist in the database to be valid.
Claiming is a single atomic database update, so two outlets scanning the same
token at the same moment cannot both claim it.

## Multiple outlets

Run **one** server, for example on a cloud VM or a PC in the head office. Every outlet
opens it in a browser and logs in with its own outlet name, so all outlets share the
same database. A token claimed at one outlet then shows as *already claimed* everywhere.

**Camera scanning needs HTTPS** on phones and tablets (localhost is exempt). Put the app behind
HTTPS, using a reverse proxy such as Caddy or nginx with Let's Encrypt. USB scanners and
typing the code work without HTTPS.

## Deploy live on Vercel

The app is ready for Vercel: `app.py` is detected as a Flask app, and `public/static` is served from Vercel's CDN.
Vercel doesn't keep files, so it needs a database. Connect **one** of these in the project's **Storage** tab:
- **Upstash Redis** (sets `KV_REST_API_URL` / `KV_REST_API_TOKEN`). The app keeps all its data under the `rwtok:` prefix, so it can share a database with other apps.
- **Neon Postgres** (sets `DATABASE_URL`).

Until a database and the settings below are in place, every page shows a **Setup needed** page listing what's missing, and `/health` reports the same.

### Option A: from the Vercel website (no command line)
1. Put this folder in a GitHub repository.
2. On vercel.com, click **Add New → Project**, import the repository, and click **Deploy**.
   The first deploy fails because there is no database yet. That is expected.
3. In the project, open **Storage → Create Database → Neon (Postgres)** and connect it to the project.
   This adds `DATABASE_URL` automatically.
4. Open **Settings → Environment Variables** and add:
   - `ADMIN_PASSWORD`: a strong password
   - `TOKEN_SECRET`: a long random string. Generate one with
     `python3 -c "import secrets; print(secrets.token_hex(32))"`.
     **Never change it later**, or every existing token will show as fake.
   - `APP_TIMEZONE`: your time zone, for example `Asia/Kolkata` (otherwise times are in UTC)
5. Open **Deployments**, then **⋯ → Redeploy**. Your app is live at `https://<project>.vercel.app`.

### Option B: with the Vercel CLI
```bash
npm i -g vercel
vercel login
vercel link                    # creates the project
vercel env add ADMIN_PASSWORD production
vercel env add TOKEN_SECRET production
vercel env add APP_TIMEZONE production
```
Then add a Neon database in the dashboard (**Storage** tab, as in step 3 above), and run:
```bash
vercel --prod
```

Vercel serves over HTTPS, so **phone camera scanning works** on the live site.

## Settings (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `ADMIN_PASSWORD` | `admin123` | Login password. **Change it.** |
| `TOKEN_SECRET` | auto-generated `.secret_key` file | Signing key. Back it up: if you lose it, all existing tokens show as fake. |
| `KV_REST_API_URL` + `KV_REST_API_TOKEN` | (none) | Upstash Redis REST API. Used first if set. |
| `DATABASE_URL` / `POSTGRES_URL` | (none) | Postgres connection string. Used when Redis isn't set. Without either, local SQLite is used. |
| `TOKEN_DB` | `tokens.db` | Local SQLite database file |
| `APP_TIMEZONE` | server time | For example `Asia/Kolkata` |
| `PORT` | `5000` | Port to run on |

For production, run it with a WSGI server, for example `pip install waitress && waitress-serve --port=5000 app:app`.
