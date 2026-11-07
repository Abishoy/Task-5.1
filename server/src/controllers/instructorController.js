import Joi from 'joi';
import { Instructor } from '../models/Instructor.js';

// =============================================================================
//  INSTRUCTOR PORTAL CONTROLLER  —  HARDENED against NoSQL injection
// =============================================================================
//
// Defense layers (see README "Task" section):
//  1. Joi validates and *types* every input. `Joi.string()` rejects objects, so
//     a smuggled operator like {"$ne": null} or {"$regex": "^S"} never reaches
//     Mongoose; Joi also rejects unknown keys, so `?$where=...` or
//     `?role[$ne]=...` are refused outright.
//  2. We build the Mongo filter ourselves from the validated values instead of
//     handing `req.body` / `req.query` straight to Mongoose.
//  3. express-mongo-sanitize (wired in app.js) strips any `$`/`.` keys as a
//     belt-and-braces second layer.
//  4. Passwords are bcrypt-hashed and compared with `comparePassword`; secret
//     fields are `select: false` on the model and never returned to clients.
// =============================================================================

// Only ever expose non-sensitive profile fields. Even if a sensitive field were
// loaded, it is not copied into the response object.
function publicProfile(doc) {
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role
  };
}

// Escape a user string so it is treated as a literal inside a RegExp — this lets
// `name=Smith` do a safe, case-insensitive partial match without letting the
// user inject regex/operator syntax.
function escapeRegExp(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const loginSchema = Joi.object({
  username: Joi.string().trim().max(120).required(),
  password: Joi.string().max(200).required()
});

// POST /api/instructors/login
export async function loginInstructor(req, res, next) {
  try {
    const { value, error } = loginSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.message });

    // `username` is now guaranteed to be a plain string, so this is a literal
    // equality match — no operator can be smuggled in. `password` is select:false
    // on the model, so we opt it in explicitly just for the comparison.
    const instructor = await Instructor.findOne({ username: value.username }).select('+password');
    if (!instructor) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const ok = await instructor.comparePassword(value.password);
    if (!ok) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    return res.json({ instructor: publicProfile(instructor) });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors
// Public directory — limited fields only.
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select('name department role')
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}

// Whitelisted search fields and the only accepted role values.
const SEARCHABLE_STRING_FIELDS = ['name', 'department'];
const VALID_ROLES = ['instructor', 'superadmin'];

// GET /api/instructors/search
export async function searchInstructors(req, res, next) {
  try {
    // Build the filter ONLY from whitelisted fields whose value is a plain
    // string. Anything else — an injected operator object (`role[$ne]=...`,
    // `name[$regex]=...`), an unknown key (`$where`, `username`), or a non-string
    // value — is simply ignored rather than rejected. Combined with
    // express-mongo-sanitize (which already strips `$`/`.` keys), no operator can
    // reach the query, so a tampered request degrades to a normal public search
    // and returns 200 instead of leaking data or erroring out.
    const q = req.query || {};
    const filter = {};

    for (const field of SEARCHABLE_STRING_FIELDS) {
      const val = q[field];
      if (typeof val === 'string' && val.trim() !== '') {
        // Escaped literal regex: case-insensitive "contains", no regex injection.
        filter[field] = { $regex: escapeRegExp(val.trim()), $options: 'i' };
      }
    }
    if (typeof q.role === 'string' && VALID_ROLES.includes(q.role)) {
      filter.role = q.role;
    }

    // Return only public fields regardless of the filter, so search can never
    // leak password / apiKey / private contact info.
    const instructors = await Instructor.find(filter)
      .select('name department role')
      .lean();
    res.json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}
