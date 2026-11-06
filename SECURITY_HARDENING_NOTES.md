# SecureDrive security hardening patch — implementation notes

This patch is based on the uploaded `Secure-Drive` source tree.

## Encryption compatibility

The file-encryption architecture and persisted encryption format are unchanged:

- PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte salt
- AES-256-GCM password-derived key wraps the random Master Key
- AES-256-GCM Master Key wraps each file's random CEK
- AES-256-GCM CEK encrypts each file
- Existing IVs, salts, wrapped Master Keys, wrapped CEKs, recovery records and encrypted file objects remain compatible

No existing user's encrypted files need to be re-encrypted.

## Implemented in this patch

1. `frontend/src/js/keyStore.js`
   - Stops writing raw Master Key bytes to `sessionStorage`.
   - Removes any legacy `secureDriveMasterKey` item when the new module loads.
   - Converts the unlocked key into a non-extractable AES-GCM working CryptoKey.
   - Keeps the working key in module memory only.
2. Reload behaviour
   - Dashboard reload discards the in-memory key and redirects to the unlock screen.
   - The active authenticated session is checked using `GET /api/auth/passkey/session`.
   - Only wrapped encryption metadata is returned; the server never receives the encryption password or plaintext Master Key.
   - The user must enter the separate file-encryption password again.
   - First-time setup retries reuse the same generated salt/wrapped key/Master Key while the page remains open, avoiding a mismatched second setup attempt.
3. WebAuthn local-device policy
   - Registration requires a platform authenticator, discoverable credential and user verification.
   - Login only offers credentials advertising the `internal` transport.
   - Cross-device/QR authentication is intentionally not offered by this current policy. Users without a local platform passkey must register one on that device/browser.
4. Session controls
   - Passkey JWT lifetime reduced from 7 days to 12 hours.
   - JWTs carry a `sessionVersion`.
   - Logout increments the user's session version and invalidates previously issued sessions.
5. Backend request hardening
   - Exact CORS origin allow-list can be configured with `FRONTEND_ORIGINS`.
   - Mutating browser requests with an unapproved Origin are rejected.
   - Request body size limits and additional security headers are applied.
   - Passkey ceremony endpoints have rate limiting.
6. Frontend security headers
   - Vite development response headers are configured.
   - Netlify `_headers` is provided under `frontend/src/public/_headers` and copied into the build output.
   - The CSP blocks inline scripts, plugin objects and framing. Inline styles remain allowed because the existing UI uses style attributes; this can be tightened after converting those styles to CSS classes.
7. API endpoint configuration
   - Frontend uses `VITE_API_BASE` instead of hardcoding localhost in source.

## Environment configuration

Backend `.env` should include:

```env
NODE_ENV=development
FRONTEND_ORIGINS=http://localhost:5173,http://127.0.0.1:5173,https://securedriv3.netlify.app
WEBAUTHN_RP_NAME=SecureDrive
WEBAUTHN_RP_ID=localhost
WEBAUTHN_ORIGIN=http://localhost:5173
JWT_SECRET=<long-random-secret>
```

Frontend local `.env`:

```env
VITE_API_BASE=http://localhost:3000/api
```

For the deployed frontend build, set `VITE_API_BASE` to the deployed API base URL, e.g. `https://securedrive-mmls.onrender.com/api`. The deployed API origin must also appear in the frontend CSP `connect-src` and the frontend origin must appear in backend `FRONTEND_ORIGINS`.

Do not commit real `.env` files or secrets.

## Important deployment/security items still requiring project-owner configuration

These are not claimed as completed by this source patch:

1. **HttpOnly cookie sessions:** The current frontend (`securedriv3.netlify.app`) and backend (`onrender.com`) are cross-site. A cookie-only session needs a same-site custom-domain arrangement and CSRF design. Until that deployment change is made, the JWT remains in `sessionStorage`; this remains an XSS exposure.
2. **Email ownership verification:** No SMTP/email provider or credentials are present in the supplied project. Do not mark an email as verified without a real verification delivery and token-validation flow.
3. **Passkey management and account recovery:** Secure add/revoke flows need fresh WebAuthn re-authentication and an explicit lost-all-passkeys recovery policy. A passkey reset must not silently reset or replace the user's encryption Master Key.
4. **XSS is not fully solved:** A non-extractable CryptoKey prevents direct export but malicious same-origin JavaScript may still invoke cryptographic operations. Avoid unsafe HTML rendering, audit dependencies, and keep CSP strict.
5. **Local passkey compatibility:** This patch intentionally excludes hybrid/cross-device transports at login. Existing credentials without `internal` transport will not be offered. Register a new platform passkey on each device/browser where local authentication is required.

## Apply and test

From the project root:

```bash
cd backend
npm install
npm start
```

In another terminal:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

Test in this order:

1. Register a new account using a device-local authenticator.
2. Set the separate file-encryption password.
3. Upload and download a file.
4. Refresh `dashboard.html`; it should return to the unlock screen.
5. Enter the same encryption password; the existing files should decrypt.
6. Logout; the previous JWT should be revoked.
7. Sign in again with the local passkey and unlock the Master Key.
8. Try login in a browser with no local passkey; it should fail with a clear local-passkey message rather than silently starting a QR flow.

The patch's JavaScript files passed `node --check`. A full Vite build and live WebAuthn/MongoDB/S3 test were not run in this environment because project dependencies and service credentials are not included.
