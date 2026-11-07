// =============================================================================
//  Instructor Portal — NoSQL injection test suite
// =============================================================================
//
// One suite, two outcomes:
//   - Against Task-5.1-solution  -> everything is GREEN (all four attacks are
//     blocked and legitimate behavior still works).
//   - Against the vulnerable Task-5.1 -> the four "Attack" blocks FAIL (the
//     injections succeed / secrets leak), while the "Legitimate behavior" block
//     stays green.
//
// The assertions check the SECURITY PROPERTY ("not logged in", "no secret field
// leaked", "no true/false oracle"), not the exact wording/status of the model
// solution, so any correct fix passes — not only this particular one.
//
// Each attack maps to a step in Flow.md.

import { jest } from '@jest/globals';
import request from 'supertest';
import mongoose from 'mongoose';

import app from '../src/app.js';
import { Instructor } from '../src/models/Instructor.js';
import {
  startDb,
  stopDb,
  seed,
  SECRET_FIELDS,
  ADMIN_PASSWORD
} from './helpers/testEnv.js';

jest.setTimeout(120000); // first run may download the mongod binary

const api = request(app);

// True if `obj` exposes any of the secret fields with a non-empty value.
function leaksSecret(obj) {
  return SECRET_FIELDS.some(
    (f) => obj != null && obj[f] !== undefined && obj[f] !== null
  );
}

beforeAll(startDb);
afterAll(stopDb);
beforeEach(seed);

// ---------------------------------------------------------------------------
// Attack 1 — Authentication bypass  (Flow.md §2)
// Sending operators instead of string credentials must NOT log anyone in.
// ---------------------------------------------------------------------------
describe('Attack 1: authentication bypass via operator injection', () => {
  test('{$ne:null}/{$ne:null} does not authenticate', async () => {
    const res = await api
      .post('/api/instructors/login')
      .send({ username: { $ne: null }, password: { $ne: null } });

    expect(res.status).not.toBe(200);
    expect([400, 401]).toContain(res.status);
    expect(res.body.instructor).toBeUndefined();
  });

  test('{$gt:""}/{$gt:""} does not authenticate', async () => {
    const res = await api
      .post('/api/instructors/login')
      .send({ username: { $gt: '' }, password: { $gt: '' } });

    expect(res.status).not.toBe(200);
    expect([400, 401]).toContain(res.status);
    expect(res.body.instructor).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Attack 2 — Leak hidden data via operator injection on /search  (Flow.md §3)
// ?role[$ne]=instructor must not return secret fields for any account.
// ---------------------------------------------------------------------------
describe('Attack 2: operator injection on /search leaks secrets', () => {
  test('?role[$ne]=instructor returns no secret fields', async () => {
    const res = await api
      .get('/api/instructors/search')
      .query({ 'role[$ne]': 'instructor' });

    expect(res.status).toBe(200);
    const instructors = res.body.instructors || [];
    const leaked = instructors.filter(leaksSecret);
    expect(leaked).toEqual([]);
  });

  test('?username[$regex]=^admin returns no secret fields', async () => {
    const res = await api
      .get('/api/instructors/search')
      .query({ 'username[$regex]': '^admin' });

    expect(res.status).toBe(200);
    const instructors = res.body.instructors || [];
    expect(instructors.filter(leaksSecret)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Attack 3 — Blind password extraction via $regex oracle  (Flow.md §4)
// A $regex password must (a) never log in and (b) not reveal whether the guess
// was right (same response for a right vs wrong prefix => no oracle). The stored
// password must also not be plaintext.
// ---------------------------------------------------------------------------
describe('Attack 3: $regex blind-extraction oracle', () => {
  test('a $regex password object never authenticates', async () => {
    const res = await api
      .post('/api/instructors/login')
      .send({ username: 'admin', password: { $regex: '^S' } });

    expect(res.status).not.toBe(200);
    expect(res.body.instructor).toBeUndefined();
  });

  test('right vs wrong regex prefix are indistinguishable (no oracle)', async () => {
    const right = await api
      .post('/api/instructors/login')
      .send({ username: 'admin', password: { $regex: '^S' } }); // matches S3cr3t...
    const wrong = await api
      .post('/api/instructors/login')
      .send({ username: 'admin', password: { $regex: '^X' } }); // matches nothing

    expect(right.status).not.toBe(200);
    expect(wrong.status).not.toBe(200);
    // The attacker learns one bit per guess only if these differ.
    expect(right.status).toBe(wrong.status);
  });

  test('admin password is not stored in plaintext', async () => {
    const admin = await Instructor.findOne({ username: 'admin' }).select('+password');
    expect(admin).toBeTruthy();
    expect(admin.password).toBeDefined();
    expect(admin.password).not.toBe(ADMIN_PASSWORD);
  });
});

// ---------------------------------------------------------------------------
// Attack 4 — Server-side JavaScript execution via $where  (Flow.md §5)
// $where injected through /search must not run as code nor leak secret fields.
// (mongodb-memory-server runs a local mongod that DOES allow $where, so on the
// vulnerable app this genuinely executes and leaks — which is what fails here.)
// ---------------------------------------------------------------------------
describe('Attack 4: $where server-side JavaScript injection', () => {
  test('?$where=this.password.length>10 leaks no secrets', async () => {
    const res = await api
      .get('/api/instructors/search')
      .query({ $where: 'this.password.length > 10' });

    expect(res.status).toBe(200);
    const instructors = res.body.instructors || [];
    expect(instructors.filter(leaksSecret)).toEqual([]);
  });

  test("?$where=apiKey.indexOf('sk_live') leaks no secrets", async () => {
    const res = await api
      .get('/api/instructors/search')
      .query({ $where: "this.apiKey && this.apiKey.indexOf('sk_live') === 0" });

    expect(res.status).toBe(200);
    const instructors = res.body.instructors || [];
    expect(instructors.filter(leaksSecret)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Legitimate behavior — must keep working after the fix. These pass on BOTH the
// vulnerable and the solution projects (the fix must not break normal use).
// ---------------------------------------------------------------------------
describe('Legitimate behavior is preserved', () => {
  test('honest login with the correct password succeeds', async () => {
    const res = await api
      .post('/api/instructors/login')
      .send({ username: 'admin', password: ADMIN_PASSWORD });

    expect(res.status).toBe(200);
    expect(res.body.instructor).toBeDefined();
    expect(res.body.instructor.role).toBe('superadmin');
  });

  test('honest login with a wrong password is rejected', async () => {
    const res = await api
      .post('/api/instructors/login')
      .send({ username: 'admin', password: 'definitely-wrong' });

    expect(res.status).toBe(401);
    expect(res.body.instructor).toBeUndefined();
  });

  test('public directory returns only safe fields', async () => {
    const res = await api.get('/api/instructors');

    expect(res.status).toBe(200);
    const instructors = res.body.instructors || [];
    expect(instructors.length).toBeGreaterThan(0);
    expect(instructors.filter(leaksSecret)).toEqual([]);
  });

  test('honest search by name finds the matching instructor', async () => {
    // Full name is used so this is green on both versions (the vulnerable
    // search does an exact match; the solution does a case-insensitive contains).
    const res = await api
      .get('/api/instructors/search')
      .query({ name: 'Prof. Alice Smith' });

    expect(res.status).toBe(200);
    const names = (res.body.instructors || []).map((i) => i.name);
    expect(names).toContain('Prof. Alice Smith');
  });
});
