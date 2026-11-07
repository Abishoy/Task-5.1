// Shared test environment for the Instructor Portal security suite.
//
// Spins up a throwaway in-memory MongoDB (a REAL mongod, so server-side
// operators like $regex and $where genuinely execute) and seeds it with the
// same accounts as src/seed/instructors.js.
//
// Seeding goes through Instructor.create(), so whatever hooks the project's own
// model defines run naturally:
//   - vulnerable project  -> no hook, password stored in plaintext
//   - solution project    -> pre('save') bcrypt hash
// The suite therefore exercises each project's real behavior with identical code.

import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import { Instructor } from '../../src/models/Instructor.js';

let mongod;

// The portal accounts under test. The `admin` superadmin is the high-value
// target holding the trophy fields (apiKey / private contact info).
export const ADMIN_PASSWORD = 'S3cr3t-Admin-Pw!';
export const ADMIN_API_KEY = 'sk_live_9f3b2c7d8e4a1b6f0d5c2a9e';

export const SEED = [
  {
    name: 'Prof. Alice Smith',
    username: 'prof.smith',
    password: 'password123',
    department: 'CS',
    role: 'instructor',
    privateEmail: 'alice.smith@university.edu',
    privatePhone: '+1-555-0101'
  },
  {
    name: 'Prof. Brian Jones',
    username: 'prof.jones',
    password: 'mathRules!',
    department: 'Math',
    role: 'instructor',
    privateEmail: 'brian.jones@university.edu',
    privatePhone: '+1-555-0102'
  },
  {
    name: 'Prof. Chen Lee',
    username: 'prof.lee',
    password: 'linalg2024',
    department: 'Math',
    role: 'instructor',
    privateEmail: 'chen.lee@university.edu',
    privatePhone: '+1-555-0103'
  },
  {
    name: 'Portal Administrator',
    username: 'admin',
    password: ADMIN_PASSWORD,
    department: 'IT',
    role: 'superadmin',
    apiKey: ADMIN_API_KEY,
    privateEmail: 'root@university.edu',
    privatePhone: '+1-555-0000'
  }
];

// Fields that must NEVER appear in any directory/search response or in an
// authentication-bypass trophy. If a test ever sees one of these on a returned
// object, a secret has leaked.
export const SECRET_FIELDS = ['password', 'apiKey', 'privateEmail', 'privatePhone'];

export async function startDb() {
  mongod = await MongoMemoryServer.create();
  await mongoose.connect(mongod.getUri(), { autoIndex: true });
}

export async function stopDb() {
  await mongoose.disconnect();
  if (mongod) await mongod.stop();
}

export async function seed() {
  await Instructor.deleteMany({});
  // create() (not insertMany) so a project's pre('save') hook runs if present.
  await Instructor.create(SEED);
}
