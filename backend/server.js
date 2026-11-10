require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');
const auth     = require('./middleware/auth');
const { startDeletionWorker } = require('./workers/accountDeletionWorker');
const { startAuditAnchorWorker } = require('./workers/auditAnchorWorker');
const { startAuditBatchWorker } =
  require('./workers/auditBatchWorker');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

const allowedOrigins = (process.env.FRONTEND_ORIGINS || [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'https://securedriv3.netlify.app'
].join(',')).split(',').map(value => value.trim()).filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    // Non-browser clients may omit Origin. Browser origins must match exactly.
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Origin not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: true, limit: '256kb' }));

// Security headers for API responses. The frontend document also needs
// deployment-level headers; see frontend/src/public/_headers.
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline'; " +
    "style-src 'self' 'unsafe-inline'; " +
    "connect-src 'self' https://securedrive-mmls.onrender.com; " +
    "font-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com"
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cache-Control', 'no-store');
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

// Explicit Origin validation for state-changing browser requests. The current
// app uses Bearer tokens; this is defence-in-depth, not a replacement for CSRF
// tokens if/when sessions migrate to cookies.
app.use('/api', (req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const origin = req.get('Origin');
  if (origin && !allowedOrigins.includes(origin)) {
    return res.status(403).json({ error: 'Request origin is not allowed' });
  }
  next();
});

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many requests, slow down' }
});

app.use(limiter);

app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'");
  next(); });


// Public routes — no token needed
app.use('/api/auth', require('./routes/auth'));
app.use('/api/auth/passkey', require('./routes/passkeyAuth'));
app.use('/api/auth/did', require('./routes/didAuth'));
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Protected routes — token required for everything below
app.use('/api/files', auth, require('./routes/files'));
app.use('/api/audit', auth, require('./routes/audit'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log("Connected DB:", mongoose.connection.name);

    startDeletionWorker();
    startAuditBatchWorker();
  })
  .catch(err => {
    console.error('MongoDB connection failed:', err);
    process.exit(1);
  });