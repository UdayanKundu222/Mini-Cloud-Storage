const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { pipeline } = require('stream/promises');
const express = require('express');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const Minio = require('minio');
const { Pool } = require('pg');

const {
  PORT = 4002,
  DATABASE_URL,
  JWT_SECRET,
  MINIO_ENDPOINT = 'minio',
  MINIO_PORT = 9000,
  MINIO_ACCESS_KEY,
  MINIO_SECRET_KEY,
  MINIO_BUCKET = 'user-files',
  MAX_UPLOAD_MB = 50,
  MIRROR_DIR, // optional: also keep a normal, openable copy of every upload here
} = process.env;
if (!DATABASE_URL || !JWT_SECRET || !MINIO_ACCESS_KEY || !MINIO_SECRET_KEY) {
  console.error('DATABASE_URL, JWT_SECRET and MinIO credentials must be set');
  process.exit(1);
}

const db = new Pool({ connectionString: DATABASE_URL });
const minio = new Minio.Client({
  endPoint: MINIO_ENDPOINT,
  port: Number(MINIO_PORT),
  useSSL: false,
  accessKey: MINIO_ACCESS_KEY,
  secretKey: MINIO_SECRET_KEY,
});
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: Number(MAX_UPLOAD_MB) * 1024 * 1024 },
});

const app = express();
app.use(express.json());

const VISIBILITIES = ['private', 'shared'];

// Tokens are issued by auth-service; this service only verifies them with the shared secret.
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

// Permission rules in one place:
//   admin  - everything
//   user   - full control of own files, read shared files
//   viewer - read shared files only
function canRead(user, file) {
  return user.role === 'admin' || file.owner_id === user.sub || file.visibility === 'shared';
}
function canModify(user, file) {
  return user.role === 'admin' || (user.role === 'user' && file.owner_id === user.sub);
}

const publicFile = (f) => ({
  id: f.id,
  name: f.original_name,
  size: Number(f.size_bytes),
  mimeType: f.mime_type,
  visibility: f.visibility,
  ownerId: f.owner_id,
  ownerEmail: f.owner_email,
  createdAt: f.created_at,
});

async function findFile(id) {
  const { rows } = await db.query(
    `SELECT f.*, u.email AS owner_email
       FROM files f JOIN users u ON u.id = f.owner_id
      WHERE f.id = $1`,
    [id],
  );
  return rows[0];
}

// ---------- Local mirror ----------
// MinIO stores objects in its own internal format, so uploads can't be opened from the
// host's file explorer. When MIRROR_DIR is set (a folder mounted from the host), every
// upload is also written there as a normal file:  <owner email>/<name> (<id prefix>).<ext>
// MinIO stays the source of truth; the mirror is a convenience copy, so mirror errors
// are logged and never fail the request.
const safeName = (s) => s.replace(/[<>:"/\\|?*\x00-\x1f]/g, '_').replace(/[. ]+$/, '').slice(0, 150) || 'file';

function mirrorPath(file) {
  const ext = path.extname(file.original_name);
  const stem = path.basename(file.original_name, ext);
  // The id prefix keeps two uploads with the same name apart and lets delete find the copy
  const name = safeName(`${stem} (${file.id.slice(0, 8)})${ext}`);
  return path.join(MIRROR_DIR, safeName(file.owner_email), name);
}

async function mirrorWrite(file, source) {
  if (!MIRROR_DIR) return;
  try {
    const dest = mirrorPath(file);
    await fs.promises.mkdir(path.dirname(dest), { recursive: true });
    if (Buffer.isBuffer(source)) await fs.promises.writeFile(dest, source);
    else await pipeline(source, fs.createWriteStream(dest));
  } catch (err) {
    console.error(`Mirror write failed for ${file.id}:`, err.message);
  }
}

async function mirrorRemove(file) {
  if (!MIRROR_DIR) return;
  await fs.promises.rm(mirrorPath(file), { force: true }).catch((err) =>
    console.error(`Mirror delete failed for ${file.id}:`, err.message),
  );
}

// At startup, copy any upload that isn't in the mirror yet (e.g. files uploaded before
// the mirror existed), straight from MinIO.
async function syncMirror() {
  if (!MIRROR_DIR) return;
  const { rows } = await db.query(
    'SELECT f.*, u.email AS owner_email FROM files f JOIN users u ON u.id = f.owner_id',
  );
  let copied = 0;
  for (const file of rows) {
    if (fs.existsSync(mirrorPath(file))) continue;
    try {
      await mirrorWrite(file, await minio.getObject(MINIO_BUCKET, file.object_key));
      copied++;
    } catch (err) {
      console.error(`Mirror sync skipped ${file.id}:`, err.message);
    }
  }
  console.log(`Mirror: ${rows.length} files tracked, ${copied} copied into ${MIRROR_DIR}`);
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function validId(req, res, next) {
  return UUID_RE.test(req.params.id) ? next() : res.status(404).json({ error: 'File not found' });
}

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

app.post('/api/files', requireAuth, requireRole('admin', 'user'), upload.single('file'), async (req, res, next) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded (field name must be "file")' });
  const visibility = req.body.visibility || 'private';
  if (!VISIBILITIES.includes(visibility)) return res.status(400).json({ error: 'Invalid visibility' });

  // Object key is never the user's filename: avoids collisions and path tricks
  const objectKey = `${req.user.sub}/${crypto.randomUUID()}`;
  const { originalname, mimetype, size, buffer } = req.file;
  try {
    await minio.putObject(MINIO_BUCKET, objectKey, buffer, size, { 'Content-Type': mimetype });
    try {
      const { rows } = await db.query(
        `INSERT INTO files (owner_id, original_name, object_key, size_bytes, mime_type, visibility)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
        [req.user.sub, originalname, objectKey, size, mimetype, visibility],
      );
      const saved = { ...rows[0], owner_email: req.user.email };
      await mirrorWrite(saved, buffer);
      res.status(201).json(publicFile(saved));
    } catch (err) {
      // Metadata insert failed: remove the object so it isn't left orphaned
      await minio.removeObject(MINIO_BUCKET, objectKey).catch(() => {});
      throw err;
    }
  } catch (err) {
    next(err);
  }
});

app.get('/api/files', requireAuth, async (req, res, next) => {
  try {
    const base = `SELECT f.*, u.email AS owner_email FROM files f JOIN users u ON u.id = f.owner_id`;
    let result;
    if (req.user.role === 'admin') {
      result = await db.query(`${base} ORDER BY f.created_at DESC`);
    } else {
      result = await db.query(
        `${base} WHERE f.owner_id = $1 OR f.visibility = 'shared' ORDER BY f.created_at DESC`,
        [req.user.sub],
      );
    }
    res.json(result.rows.map(publicFile));
  } catch (err) {
    next(err);
  }
});

app.get('/api/files/:id/download', requireAuth, validId, async (req, res, next) => {
  try {
    const file = await findFile(req.params.id);
    // 404 rather than 403 so other users' private file IDs aren't confirmed to exist
    if (!file || !canRead(req.user, file)) return res.status(404).json({ error: 'File not found' });

    const stream = await minio.getObject(MINIO_BUCKET, file.object_key);
    res.setHeader('Content-Type', file.mime_type);
    res.setHeader('Content-Length', file.size_bytes);
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(file.original_name)}`);
    stream.on('error', next);
    stream.pipe(res);
  } catch (err) {
    next(err);
  }
});

app.patch('/api/files/:id', requireAuth, validId, async (req, res, next) => {
  try {
    const { visibility } = req.body;
    if (!VISIBILITIES.includes(visibility)) return res.status(400).json({ error: 'Invalid visibility' });
    const file = await findFile(req.params.id);
    if (!file || !canRead(req.user, file)) return res.status(404).json({ error: 'File not found' });
    if (!canModify(req.user, file)) return res.status(403).json({ error: 'Forbidden' });

    await db.query('UPDATE files SET visibility = $1 WHERE id = $2', [visibility, file.id]);
    res.json(publicFile({ ...file, visibility }));
  } catch (err) {
    next(err);
  }
});

app.delete('/api/files/:id', requireAuth, validId, async (req, res, next) => {
  try {
    const file = await findFile(req.params.id);
    if (!file || !canRead(req.user, file)) return res.status(404).json({ error: 'File not found' });
    if (!canModify(req.user, file)) return res.status(403).json({ error: 'Forbidden' });

    // Delete the metadata first: if removing the object then fails, we are left with an
    // unreachable orphan object (harmless) instead of a record pointing at nothing.
    await db.query('DELETE FROM files WHERE id = $1', [file.id]);
    await minio.removeObject(MINIO_BUCKET, file.object_key).catch((err) =>
      console.error(`Orphaned object ${file.object_key}:`, err.message),
    );
    await mirrorRemove(file);
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError) {
    const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
    return res.status(status).json({ error: err.message });
  }
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

async function ensureBucket() {
  if (!(await minio.bucketExists(MINIO_BUCKET))) {
    await minio.makeBucket(MINIO_BUCKET);
    console.log(`Created bucket ${MINIO_BUCKET}`);
  }
}

ensureBucket()
  .then(() => app.listen(PORT, () => console.log(`file-service listening on ${PORT}`)))
  .then(() => syncMirror().catch((err) => console.error('Mirror sync failed:', err.message)))
  .catch((err) => {
    console.error('Could not reach MinIO:', err.message);
    process.exit(1); // Docker's restart policy will retry
  });
