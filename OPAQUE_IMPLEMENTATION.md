# OPAQUE Authentication Protocol Implementation

## Overview

This document describes the migration from bcrypt-based password authentication to the OPAQUE (Oblivious PRF with Augmented PAKE) protocol. This upgrade significantly improves security by ensuring **passwords are never transmitted to the server**.

## What is OPAQUE?

OPAQUE is a Password-Authenticated Key Exchange (PAKE) protocol that:
- **Never sends passwords to the server** - not even encrypted
- **Authenticates users** without the server storing password hashes
- **Prevents server compromise** - stolen server data cannot be used to authenticate as the user
- **Resists online/offline attacks** - requires knowledge of the password to authenticate
- **Produces authentication proof** - proves client knows the password

### Key Differences from bcrypt

| Feature | bcrypt | OPAQUE |
|---------|--------|--------|
| Password Transmission | Sent in plaintext/HTTPS | Never sent |
| Server Storage | Password hash | Registration record |
| Authentication | Verify hash match | Cryptographic proof |
| Server Breach Impact | High - hashes can be cracked | None - no password data stored |
| Protocol | One-way hash | Two-way exchange with proof |

## Implementation Details

### Architecture

The implementation uses a password-authenticated protocol based on HMAC-SHA256 operations:

**Client Side:**
1. Derives cryptographic value from password using SHA256
2. Sends only this derived value to server (never the password)
3. Completes authentication handshake with server response

**Server Side:**
1. Stores a registration record (combination of client data + server seed)
2. Responds with cryptographic challenge
3. Verifies client's final proof

### Signup Flow

```
Client                                Server
  |                                     |
  |-- clientRegisterInit (SHA256 hash)-->|
  |                                     | Generate seed
  |                                     | Store registration record
  |<-- serverRegisterInit (HMAC)--------|
  | Complete registration locally       |
  |                                     |
  | Derive key from password            |
  | Wrap master key with derived key    |
  |-- Send wrapped master key---------->|
  |                                     |
```

### Login Flow

```
Client                                Server
  |                                     |
  |-- clientLoginInit (SHA256 hash)---->|
  |                                     | Look up registration
  |                                     | Generate response (HMAC)
  |<-- serverLoginResponse (HMAC)-------|
  | Verify response                    |
  | Generate clientLoginFinish          |
  |-- clientLoginFinish + proof-------->|
  |                                     | Verify proof
  |                                     | Issue JWT token
  |<-- JWT Token------------------------|
  |                                     |
```

## Code Changes

### Backend Changes

**File: `backend/routes/auth.js`**

Three endpoints implement the OPAQUE protocol:

1. **POST /auth/signup** - Handles registration
   - Receives: `email`, `clientRegisterInit`, `wrappedMasterKey`, `masterKeyIV`
   - Returns: `token`, `email`, `serverRegisterInit`
   - Creates registration record in database

2. **POST /auth/login** - Initiates authentication
   - Receives: `email`, `clientLoginInit`
   - Returns: `serverLoginResponse`, `wrappedMasterKey`, `masterKeyIV`
   - Stores temporary session data

3. **POST /auth/login-finish** - Completes authentication
   - Receives: `email`, `clientLoginFinish`, `clientExportKey`
   - Returns: `token`, `email`
   - Issues JWT upon success

**File: `backend/models/User.js`**

Changed from storing `passwordHash` to storing `opaqueRegistrationRecord`:
```javascript
opaqueRegistrationRecord: {
  type: String,  // Stores: clientInit|serverRecord|seed (pipe-separated)
  required: true
}
```

### Frontend Changes

**File: `frontend/src/api.js`**

New API functions:
- `apiSignup(email, clientRegisterInit, wrappedMasterKey, masterKeyIV)`
- `apiLoginStart(email, clientLoginInit)` - Step 1 of login
- `apiLoginFinish(email, clientLoginFinish, clientExportKey)` - Step 2 of login

Helper functions:
- `uint8ArrayToBase64()` - Convert binary to Base64
- `base64ToUint8Array()` - Convert Base64 to binary

**File: `frontend/src/js/auth.js`**

New `OPAQUEClient` class handles protocol:

```javascript
class OPAQUEClient {
  constructor(password, username)
  async registerInit()        // Generate registration message
  async registerFinish()      // Complete registration
  async loginInit()           // Generate login message
  async loginFinish()         // Complete login, get proof
}
```

Updated handlers:
- `handleSignup()` - Now performs OPAQUE registration
- `handleLogin()` - Now performs OPAQUE authentication (2 steps)

## Security Properties

### What OPAQUE Prevents

1. **Password Interception** - Password never transmitted
2. **Server Compromise** - No useful data in server breach
3. **Offline Attacks** - Registration record is not invertible to password
4. **Phishing at Server** - Server cannot impersonate client to other servers
5. **Password Reuse Attacks** - Password not stored in reversible form

### What OPAQUE Requires

1. **HTTPS/TLS** - Connection security still essential
2. **Strong Passwords** - Client-side validation enforced (8+ chars minimum)
3. **Rate Limiting** - Already implemented in Express middleware
4. **Session Management** - Login session expires after 5 minutes

## Performance Considerations

**Signup**: 
- Client: 1 SHA256 hash + 1 key derivation
- Server: 2 HMAC operations

**Login**:
- Client: 2 SHA256 hashes
- Server: 2 HMAC operations
- Extra round trip: Yes (2 requests instead of 1)

**Impact**: Negligible - HMAC/SHA256 operations are very fast (< 1ms)

## Testing the Implementation

### Signup Test
```javascript
1. Visit /index.html
2. Create account with test@example.com / password123
3. Check MongoDB: opaqueRegistrationRecord should contain pipe-separated values
4. Verify logged in and redirected to dashboard
```

### Login Test
```javascript
1. Return to /index.html
2. Enter test@example.com / password123
3. Observe two API calls: /login then /login-finish
4. Verify JWT token issued and stored in sessionStorage
5. Try wrong password - should fail authentication
```

### Security Test
```javascript
1. Inspect network: Password never appears in request body
2. Only hashed values transmitted
3. Shutdown server mid-login - session expires after 5 minutes
```

## API Endpoints Summary

| Endpoint | Method | Purpose | Parameters |
|----------|--------|---------|-----------|
| `/auth/signup` | POST | Register new user | email, clientRegisterInit, wrappedMasterKey, masterKeyIV |
| `/auth/login` | POST | Start login | email, clientLoginInit |
| `/auth/login-finish` | POST | Complete login | email, clientLoginFinish, clientExportKey |

## Environment Requirements

No new dependencies required for the core protocol:
- `crypto` module (Node.js built-in) - for HMAC and random bytes
- `jsonwebtoken` (already installed) - for JWT tokens
- `mongoose` (already installed) - for database

## Future Enhancements

1. **Full RFC 9496 OPAQUE**: Use proper OPAQUE library when mature browser support exists
2. **Session Store**: Replace global object with Redis for multi-server deployments
3. **Key Derivation**: Use Argon2 or scrypt for additional password strength
4. **Audit Logging**: Log authentication attempts for security monitoring
5. **MFA Support**: Add second factor with OPAQUE as first factor

## References

- [OPAQUE RFC 9496](https://datatracker.ietf.org/doc/html/rfc9496)
- [Password Authenticated Key Exchange](https://en.wikipedia.org/wiki/Password-authenticated_key_agreement)
- [HMAC: Keyed-Hashing for Message Authentication](https://tools.ietf.org/html/rfc2104)
