require('dotenv').config();

const mongoose = require('mongoose');
const User = require('../models/User');

async function promoteAdmin() {
  try {
    if (!process.env.ADMIN_EMAIL) {
      throw new Error('ADMIN_EMAIL is required');
    }

    await mongoose.connect(process.env.MONGO_URI);

    const email = process.env.ADMIN_EMAIL.toLowerCase().trim();

    const user = await User.findOneAndUpdate(
      { email },
      { $set: { role: 'ADMIN' } },
      { new: true }
    );

    if (!user) {
      throw new Error('Admin account not found. Register first.');
    }

    console.log('Administrator provisioned:', user.email);
  } catch (err) {
    console.error('Admin provisioning failed:', err.message);
    process.exitCode = 1;
  } finally {
    await mongoose.disconnect();
  }
}

promoteAdmin();