const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const { PORT = 4001, DATABASE_URL, JWT_SECRET, JWT_EXPIRES_IN = '1h' } = process.env;
if (!DATABASE_URL || !JWT_SECRET) {
  console.error('DATABASE_URL and JWT_SECRET must be set');
  process.exit(1);
}

const db = new Pool({ connectionString: DATABASE_URL });
const app = express();
app.use(express.json());

const ROLES = ['admin', 'user', 'viewer'];
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const publicUser = (u) => ({ id: u.id, email: u.email, role: u.role, createdAt: u.created_at });

function signToken(user) {
  return jwt.sign({ sub: user.id, email: user.email, role: user.role }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
  });
}

function requireAuth(req, res, next) {
  const [scheme, token] = (req.headers.authorization || '').split(' ');
  if (scheme !== 'Bearer' || !token) return res.status(401).json({ error: 'Missing token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

const requireRole = (...roles) => (req, res, next) =>
  roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'Forbidden' });

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

app.post('/api/auth/register', async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'Invalid email' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const hash = await bcrypt.hash(password, 10);
    // The very first account becomes admin so the system can be bootstrapped.
    const { rows } = await db.query(
      `INSERT INTO users (email, password_hash, role)
       VALUES ($1, $2, CASE WHEN EXISTS (SELECT 1 FROM users) THEN 'user' ELSE 'admin' END)
       RETURNING *`,
      [email, hash],
    );
    res.status(201).json({ token: signToken(rows[0]), user: publicUser(rows[0]) });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Email already registered' });
    next(err);
  }
});

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const { rows } = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = rows[0];
    // Same message for unknown email and wrong password, so emails can't be probed
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    res.json({ token: signToken(user), user: publicUser(user) });
  } catch (err) {
    next(err);
  }
});

app.get('/api/auth/me', requireAuth, async (req, res, next) => {
  try {
    const { rows } = await db.query('SELECT * FROM users WHERE id = $1', [req.user.sub]);
    if (!rows[0]) return res.status(404).json({ error: 'User not found' });
    res.json(publicUser(rows[0]));
  } catch (err) {
    next(err);
  }
});

app.get('/api/auth/users', requireAuth, requireRole('admin'), async (_req, res, next) => {
  try {
    const { rows } = await db.query('SELECT * FROM users ORDER BY id');
    res.json(rows.map(publicUser));
  } catch (err) {
    next(err);
  }
});

app.patch('/api/auth/users/:id/role', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const { role } = req.body;
    if (!ROLES.includes(role)) return res.status(400).json({ error: `Role must be one of ${ROLES.join(', ')}` });
    if (id === req.user.sub) return res.status(400).json({ error: 'You cannot change your own role' });

    const { rows } = await db.query('UPDATE users SET role = $1 WHERE id = $2 RETURNING *', [role, id]);
    if (!rows[0]) return res.status(404).json({ error: 'User not found' });
    res.json(publicUser(rows[0]));
  } catch (err) {
    next(err);
  }
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => console.log(`auth-service listening on ${PORT}`));
