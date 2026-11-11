# Adults Club — security event logging

## Run
Requires Node.js 20+. No npm dependencies.

PowerShell:
```powershell
$env:ADMIN_TOKEN = "replace-with-a-random-secret-of-at-least-32-characters"
npm start
```
Visit http://127.0.0.1:3000. Log entries appear in `data/visitors-YYYY-MM-DD.jsonl`.

Read the most recent 200 events for a date (PowerShell):
```powershell
$headers = @{ Authorization = "Bearer $env:ADMIN_TOKEN" }
Invoke-RestMethod -Headers $headers -Uri "http://127.0.0.1:3000/api/admin/visitors?date=2026-11-11"
```
Never expose the admin endpoint without HTTPS, authentication and network restrictions. The sample uses bearer-token auth and local-only binding by default.

## Production checklist
- Put Node behind Nginx with HTTPS; bind Node to 127.0.0.1, and protect `/api/admin/` with additional IP allowlisting or VPN access.
- To enable real visitor IP forwarding, set `TRUST_PROXY=1` **only** when Nginx is the sole path to Node and overwrites forwarding headers:
```nginx
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header Host $host;
proxy_set_header X-Forwarded-Proto $scheme;
```
- If using Cloudflare or another upstream CDN, configure trusted real-IP restoration in Nginx first; never blindly trust a user-provided header.
- Store `ADMIN_TOKEN` in secret management; use a long random token (32+ characters). Rotate if exposed.
- Back up and protect logs; enforce retention. Set `RETENTION_DAYS` (default 30).
- For high traffic or incident evidence, replace local JSONL with centralized, access-controlled, tamper-evident logging and alerting.
- Ensure time synchronization, disk monitoring, access audits, incident procedures, and security testing.
- Inform users in a privacy notice, establish a lawful basis, and limit collection to necessary security data.

## What is recorded
UTC timestamp, visitor IP, event ID, page path, method, User-Agent, approximate OS/browser/device category, and referrer **origin**. No passwords, cookies, URL query strings, or GPS coordinates. Browser/device information can be inaccurate or spoofed. The page is still a static demo; login is not implemented.

## Limitations
This is a hardened development/starter implementation, **not** a complete production security platform. No geolocation, fingerprinting, identity lookup or ISP subscriber identification is included. Public IP and device metadata cannot identify a person on their own.
