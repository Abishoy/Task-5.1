import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

// Instructor Portal account.
//
// Hardened against the NoSQL injection lab:
//  - Passwords are hashed with bcrypt (pre-save hook) and never stored in
//    plaintext, so a blind $regex oracle can no longer rebuild them and a leak
//    does not expose a usable secret.
//  - The sensitive "trophy" fields (password, apiKey, private contact info) are
//    `select: false`, so they are stripped from every query result by default
//    and can only be pulled in deliberately (e.g. `.select('+password')` during
//    login). No handler can accidentally return them to a client.
const instructorSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true, trim: true },
    // Stores the bcrypt hash, never the plain-text password. Hidden by default.
    password: { type: String, required: true, select: false },
    department: { type: String },
    role: { type: String, default: 'instructor' }, // 'instructor' | 'superadmin'

    // Sensitive fields: hidden by default so they never leak through a query.
    apiKey: { type: String, select: false },
    privateEmail: { type: String, select: false },
    privatePhone: { type: String, select: false }
  },
  { timestamps: true }
);

// Hash the password whenever it is set or changed. Runs on `save()` and on
// `create()` (including `create([...])`), so the seed is hashed too.
instructorSchema.pre('save', async function hashPassword(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

instructorSchema.methods.comparePassword = async function comparePassword(candidate) {
  return bcrypt.compare(candidate, this.password);
};

export const Instructor = mongoose.model('Instructor', instructorSchema);
