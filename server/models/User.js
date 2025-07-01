import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  twoFactorSecret: {
    type: String,
    required: false
  },
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },
  hardToken: {
    type: String,
    required: false
  },
  hardTokenExpires: {
    type: Date,
    required: false
  },
  lastLogin: {
    type: Date
  },
  isActive: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Check if hard token is valid
userSchema.methods.isHardTokenValid = function(token) {
  return this.hardToken === token && 
         this.hardTokenExpires && 
         this.hardTokenExpires > new Date();
};

export default mongoose.model('User', userSchema);