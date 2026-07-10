# 🔐 SecureDrive

> **Privacy-preserving cloud storage — your files are encrypted before they leave your device.**

SecureDrive is a web-native cloud storage application where all encryption and decryption happens entirely in your browser. The server stores only encrypted bytes — even a complete server breach exposes nothing meaningful. Built at IIT Dharwad as a Bachelor's Thesis Project.

---

## 🌐 Live Deployment

| Service | URL |
|---------|-----|
| **Frontend** | `securedriv3.netlify.app` |
| **Backend API** | `https://securedrive-mmls.onrender.com` |
| **AWS S3 Region** | `ap-south-1` (Mumbai) |

> **Note:** Backend is hosted on Render's free tier. First request after inactivity may take 30–60 seconds to wake up (cold start).

---

## ⚠️ Branch Status

| Branch | Purpose | Status |
|--------|---------|--------|
| `production` | Active development — current working version | ✅ Live |
| `main` | Stable release branch | ⏳ Pending merge from `production` |

> All current development happens on the `production` branch. The `main` branch will be updated once the BTP research layer (blockchain audit trail) is complete and tested.

---

## How It Works

### The Core Idea

Most cloud storage (Google Drive, Dropbox) encrypts your files **on their servers** — meaning they hold the keys and can technically read your data. SecureDrive flips this: files are encrypted **before they leave your browser**, using keys that only you control.

### Three-Layer Key Hierarchy

```
Your Password
      │
      ▼
 PBKDF2 (600,000 iterations — NIST SP 800-132, 2023)
      │
      ▼
 Password-Derived Key  ──encrypts──►  Master Key (wrapped)  ──► stored in MongoDB
                                             │
                                             ▼
                                  per-file Content Encryption Key (CEK)
                                             │
                                             ▼
                                      AES-256-GCM
                                             │
                                             ▼
                                    Encrypted file  ──► stored in AWS S3
```

**What the server stores:** encrypted bytes, wrapped keys, IVs — nothing readable without your password.

**What the server never sees:** your password, Master Key, any CEK, or any plaintext file.

### User Flow

| Action | What happens |
|--------|-------------|
| **Signup** | Browser derives key from password → generates Master Key → wraps it → sends only the wrapped key to server |
| **Login** | Server returns wrapped Master Key → browser unwraps using password → Master Key lives in memory only |
| **Upload** | Browser generates CEK → encrypts file → wraps CEK → sends encrypted file + wrapped CEK to server |
| **Download** | Server returns wrapped CEK + encrypted file → browser unwraps CEK → decrypts file locally |

---

## Encryption Primitives

| Operation | Algorithm | Standard |
|-----------|-----------|---------|
| File encryption | AES-256-GCM | NIST FIPS 197 |
| Key derivation | PBKDF2-SHA256, 600,000 iterations | NIST SP 800-132 (2023) |
| Key wrapping | AES-GCM wrap/unwrap | Web Crypto API |
| Password hashing (server) | bcrypt, cost factor 12 | Industry standard |
| Session tokens | JWT, 7-day expiry | RFC 7519 |
| All crypto | Web Crypto API | W3C Standard |

---

## Security

### Threat Model

This project has been formally analysed using:
- **STRIDE** threat model
- **MITRE ATT&CK Enterprise** framework (13 techniques assessed)
- **OWASP Top 10:2025** compliance (10 risks assessed)

### Security Status

| Framework | Mitigated | Partial | Open |
|-----------|-----------|---------|------|
| MITRE ATT&CK (13 techniques) | 12/13 | 1/13 | 0/13 |
| OWASP Top 10:2025 | 9/10 | 1/10 | 0/10 |

### Identified and Fixed Vulnerabilities

| ID | Description | MITRE | Status |
|----|-------------|-------|--------|
| SD-V001 | Authentication bypass — login accepted email with no password check | T1078 Valid Accounts | ✅ Fixed |

### Security Controls Implemented

- AES-256-GCM with unique IV per file
- PBKDF2 with 600,000 iterations (NIST 2023 compliant)
- bcrypt password hashing (cost factor 12)
- JWT authentication with expiry
- Server-side file ownership validation on every route
- Rate limiting (100 requests / IP / 15 min)
- Filename sanitisation (strips dangerous characters)
- Content Security Policy (CSP) headers
- X-Frame-Options, X-Content-Type-Options, Referrer-Policy headers
- Master Key stored as non-extractable Web Crypto key (never in sessionStorage)
- HTTPS enforced on all deployed services

### Partial Mitigations

- **T1498 / A09 (DDoS + Audit Logging):** Application-level rate limiting active. Network-level DDoS protection (Cloudflare) planned on custom domain acquisition. Structured audit logging planned via blockchain audit trail (BTP research phase).

---

## Tech Stack

### Backend
| Component | Technology |
|-----------|-----------|
| Runtime | Node.js |
| Framework | Express.js |
| Database | MongoDB Atlas (Mongoose) |
| File Storage | AWS S3 (ap-south-1) |
| Authentication | JWT + bcrypt |
| File Upload | Multer (memory storage) |

### Frontend
| Component | Technology |
|-----------|-----------|
| Language | Vanilla JavaScript (ES Modules) |
| Crypto | Web Crypto API (browser built-in) |
| HTTP Client | Fetch API |
| Hosting | Netlify |

### Development Frameworks Used
- NIST SP 800-218 Secure Software Development Framework (SSDF)
- MITRE ATT&CK Enterprise
- OWASP Top 10:2025

---

## Project Structure

```
SecureDrive/
├── backend/
│   ├── config/
│   │   └── s3.js              # AWS S3 client and helpers
│   ├── middleware/
│   │   └── auth.js            # JWT verification middleware
│   ├── models/
│   │   ├── User.js            # User schema (email, passwordHash, wrappedMasterKey)
│   │   └── File.js            # File schema (owner, storagePath, wrappedCEK, IVs)
│   ├── routes/
│   │   ├── auth.js            # POST /signup, POST /login
│   │   └── files.js           # Upload, list, meta, download, delete
│   ├── .env                   # ← never committed (see .gitignore)
│   ├── .gitignore
│   ├── package.json
│   └── server.js              # Express app entry point
│
└── frontend/
    └── src/
        ├── index.html         # Single-page app (auth + dashboard)
        ├── crypto.js          # All Web Crypto operations
        ├── api.js             # Backend API calls
        ├── css/
        │   ├── auth.css
        │   └── dashboard.css
        └── js/
            └── app.js         # App logic (auth + file management)
```

---

## Running Locally

### Prerequisites

- Node.js v18+
- MongoDB Atlas account (free tier)
- AWS account with S3 bucket

### Backend Setup

```bash
git clone https://github.com/nidhi-005/SecureDrive
cd SecureDrive/backend
npm install
```

Create `backend/.env`:
```
MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/securedrive
JWT_SECRET=your_long_random_secret_here
PORT=3000
AWS_ACCESS_KEY_ID=your_aws_key
AWS_SECRET_ACCESS_KEY=your_aws_secret
AWS_REGION=ap-south-1
AWS_BUCKET_NAME=your-bucket-name
```

```bash
node server.js
# Server running on port 3000
# Connected DB: securedrive
```

### Frontend Setup

```bash
cd ../frontend
npm install
npm run dev
# Open http://localhost:5173
```

---

## API Reference

All `/api/files/*` routes require `Authorization: Bearer <token>` header.

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/signup` | ❌ | Create account |
| POST | `/api/auth/login` | ❌ | Login, returns JWT + wrapped master key |
| POST | `/api/files/upload` | ✅ | Upload encrypted file |
| GET | `/api/files` | ✅ | List user's files |
| GET | `/api/files/:id/meta` | ✅ | Get crypto metadata for decryption |
| GET | `/api/files/:id/download` | ✅ | Download encrypted file bytes |
| DELETE | `/api/files/:id` | ✅ | Delete file from S3 and MongoDB |
| GET | `/api/health` | ❌ | Health check (keep-alive ping) |

---

## Planned Research Extensions (BTP Phase 2)

- **Blockchain-anchored audit trail** — every file access event hashed and anchored to Ethereum Sepolia testnet. Users can independently verify access history without trusting the server. (Raghuveer Verma, Aug–Dec 2026)
- **Penetration testing** — OWASP ZAP against deployed system (Aug–Dec 2026)
- **Cloudflare DDoS protection** — on custom domain acquisition
- **Formal BTP report** — combining all documentation (Nov 2026)

---

## Documentation

| Document | Description |
|----------|-------------|
| `SecureDrive_Literature_Survey_v2.docx` | Comparative analysis of Cryptomator, Proton Drive, Filen |
| `SecureDrive_Security_Analysis.docx` | MITRE ATT&CK + OWASP Top 10:2025 threat analysis |
| `SecureDrive_BTP_Response.docx` | Responses to supervisor feedback |

---

## Authors

**Yashaswini L** — IIT Dharwad, CSE (`cs23bt060@iitdh.ac.in`)
**Raghuveer Verma** — IIT Dharwad, CSE

*BTP Project under Prof. Siba Narayan Swain*
*Department of Computer Science and Engineering, IIT Dharwad*

---

## License

MIT License — see `LICENSE` for details.
