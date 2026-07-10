require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const mongoose = require('mongoose');
const auth     = require('./middleware/auth');

const app = express();
app.use(cors({
  origin: [
    'http://localhost:5173',
    'http://127.0.0.1:5173',
    'https://securedriv3.netlify.app'  // your actual Vercel URL
  ],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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
  next();
});

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log("Connected DB:", mongoose.connection.name);
  });

const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,                  // max 100 requests per IP
  message: { error: 'Too many requests, slow down' }
});

app.use(limiter);

app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'");
  next(); });


// Public routes — no token needed
app.use('/api/auth', require('./routes/auth'));

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Protected routes — token required for everything below
app.use('/api/files', auth, require('./routes/files'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));