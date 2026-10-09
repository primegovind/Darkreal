# StreamHub 18+ — adult-content platform starter

A dark, responsive starter for a lawful adults-only video-sharing site. It includes user accounts, video uploads and playback, search, likes/comments, an admin dashboard, report handling, a basic date-of-birth age gate, and advertising placeholders.

## Important age-verification limitation
The included date-of-birth check is **self-declaration only**. It is not secure identity/age verification and may not meet legal requirements in your jurisdiction. Before public launch, integrate a reputable third-party age-verification provider server-side and store only the minimum verification result/token (not identity documents or selfies). Do not describe this starter as legally compliant until reviewed by a qualified professional.

## Requirements
- Node.js 20 or newer
- npm

## Run locally
1. Extract the ZIP.
2. Open a terminal in the `streamhub` folder.
3. Install dependencies: `npm install`
4. Copy `.env.example` to `.env`.
5. Edit `.env` and set a unique long `SESSION_SECRET`, your `ADMIN_EMAIL`, and a strong `ADMIN_PASSWORD`.
6. Start: `npm start`
7. Open `http://localhost:3000`.

## Admin login
Log in using `ADMIN_EMAIL` and `ADMIN_PASSWORD` from `.env`. Do not use example credentials. Keep `.env` private.

## Included features
- 18+ date-of-birth age gate (self-declaration prototype only)
- Registration/login/logout with bcrypt password hashing
- Video uploads with title, description and category
- Video player, search, view counts, likes and comments
- User report workflow for suspected minors, non-consensual intimate content, copyright, exploitation, illegal content and other concerns
- Admin dashboard: manage users, hide/publish/delete videos, review reports
- Media route gated by age verification and video visibility
- Adult advertising placeholder; no ad network is preconfigured

## Production checklist — required before public use
- Integrate legally appropriate third-party age verification; enforce it on the server and media delivery. A client-only age gate is insufficient.
- Add robust moderation and incident response. Immediately restrict suspected underage/non-consensual content, preserve appropriate audit logs, and follow applicable reporting/takedown laws.
- Establish uploader identity/age checks, explicit consent and model-release verification, rights verification, repeat-infringer policy, and a documented takedown process. Do not allow content involving minors, coercion, trafficking, non-consensual intimate imagery, or other illegal/exploitative material.
- Add rate limiting, email verification, password reset, CSRF protections, logging, anti-malware scanning and isolated media transcoding.
- Use a production database (e.g. managed PostgreSQL), durable object storage (S3-compatible/R2), CDN, and persistent session store (e.g. Redis). The included JSON database and local disk are only for prototyping and can be lost on redeploy.
- Put the site behind HTTPS, set `NODE_ENV=production`, rotate secrets, and configure secure backups.
- Integrate only an advertising provider whose current written policies explicitly allow your content category and region. Approval is not guaranteed; many mainstream ad providers prohibit adult content. Never load ads before required age verification or where prohibited.
- Have local counsel review age-verification, privacy, content-hosting, and takedown obligations for every region where you operate.

## Deployment
Deploy to a Node-compatible host that supports persistent storage, or configure object storage and a database first. Set environment variables in the host dashboard:
- `SESSION_SECRET`
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD`
- `NODE_ENV=production`
- `PORT` (if required by host)
- `MAX_UPLOAD_MB` (default 500)

Build/start command: `npm install` / `npm start`.

Do not commit `.env`, uploaded media, or user data to a public repository.
