require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const mongoose = require('mongoose');
const auth     = require('./middleware/auth');

const app = express();
app.use(cors({
  origin: [
    'http://localhost:5173',
    'https://securedrive.vercel.app'  // your actual Vercel URL
  ],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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

// Public routes — no token needed
app.use('/api/auth', require('./routes/auth'));

// Protected routes — token required for everything below
app.use('/api/files', auth, require('./routes/files'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));