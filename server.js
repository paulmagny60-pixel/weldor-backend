// ============================================================
// WELDOR SAAS - BACKEND NODE.JS / EXPRESS
// ============================================================
require('dotenv').config();
const express     = require('express');
const { Pool }    = require('pg');
const bcrypt      = require('bcryptjs');
const jwt         = require('jsonwebtoken');
const cors        = require('cors');
const rateLimit   = require('express-rate-limit');
const Joi         = require('joi');
const crypto      = require('crypto');

const app = express();

// ============================================================
// CONFIGURATION DB
// ============================================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// ============================================================
// MIDDLEWARES
// ============================================================
app.use(express.json());
app.use(cors({
  origin: function(origin, callback) {
    // Autoriser les requêtes sans origin (Postman, curl) et toutes les origines autorisées
    const allowed = [
      'http://localhost:5173',
      'http://localhost:3000',
      'https://weldor-soudure-mv09.netlify.app',
    ];
    if (!origin || allowed.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
}));

// Répondre aux preflight OPTIONS sur toutes les routes
app.options('*', cors());

// Rate limiting sur les routes d'auth
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Trop de tentatives. Réessayez dans 15 minutes.' },
});

// ============================================================
// HELPERS JWT
// ============================================================
const generateAccessToken = (user) =>
  jwt.sign(
    { id: user.id, company_id: user.company_id, role: user.role, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '15m' }
  );

const generateRefreshToken = () => crypto.randomBytes(64).toString('hex');

// ============================================================
// MIDDLEWARE AUTH
// ============================================================
const authenticate = async (req, res, next) => {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer '))
    return res.status(401).json({ error: 'Token manquant' });
  try {
    const token = header.split(' ')[1];
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token invalide ou expiré' });
  }
};

const requireOnboarding = async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      'SELECT onboarding_done FROM companies WHERE id = $1',
      [req.user.company_id]
    );
    if (!rows[0]?.onboarding_done) {
      return res.status(403).json({ error: 'Onboarding requis', code: 'ONBOARDING_REQUIRED' });
    }
    next();
  } catch (err) { next(err); }
};

// ============================================================
// VALIDATION SCHEMAS
// ============================================================
const registerSchema = Joi.object({
  company_name: Joi.string().min(2).max(255).required(),
  email:        Joi.string().email().required(),
  password:     Joi.string().min(8).required(),
  confirm_password: Joi.string().valid(Joi.ref('password')).required()
    .messages({ 'any.only': 'Les mots de passe ne correspondent pas' }),
});

const loginSchema = Joi.object({
  email:    Joi.string().email().required(),
  password: Joi.string().required(),
});

const onboardingSchema = Joi.object({
  name:                Joi.string().min(2).max(255).required(),
  email:               Joi.string().email().allow('', null),
  phone:               Joi.string().allow('', null),
  address:             Joi.string().allow('', null),
  siret:               Joi.string().allow('', null),
  tva_number:          Joi.string().allow('', null),
  default_hourly_rate: Joi.number().min(0).default(0),
  currency:            Joi.string().default('EUR'),
});

// ============================================================
// ROUTES AUTH
// ============================================================

// POST /api/auth/register
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { error, value } = registerSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });
    const { company_name, email, password } = value;

    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0)
      return res.status(409).json({ error: 'Cet email est déjà utilisé' });

    let slug = company_name.toLowerCase()
      .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
      .replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

    const slugCheck = await pool.query('SELECT id FROM companies WHERE slug LIKE $1', [`${slug}%`]);
    if (slugCheck.rows.length > 0) slug = `${slug}-${Date.now()}`;

    const password_hash = await bcrypt.hash(password, 12);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const companyRes = await client.query(
        `INSERT INTO companies (name, slug) VALUES ($1, $2) RETURNING id`,
        [company_name, slug]
      );
      const company_id = companyRes.rows[0].id;
      const userRes = await client.query(
        `INSERT INTO users (company_id, email, password_hash, role)
         VALUES ($1, $2, $3, 'owner') RETURNING id, company_id, role, email`,
        [company_id, email.toLowerCase(), password_hash]
      );
      const user = userRes.rows[0];
      await client.query('COMMIT');

      const accessToken  = generateAccessToken(user);
      const refreshToken = generateRefreshToken();
      const expiresAt    = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
      await pool.query(
        'INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)',
        [user.id, refreshToken, expiresAt]
      );
      return res.status(201).json({
        message: 'Compte créé avec succès',
        access_token: accessToken, refresh_token: refreshToken,
        user: { id: user.id, email: user.email, role: user.role,
                company_id, company_name, onboarding_done: false },
      });
    } catch (err) {
      await client.query('ROLLBACK'); throw err;
    } finally { client.release(); }
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { error, value } = loginSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });
    const { email, password } = value;

    const result = await pool.query(
      `SELECT u.id, u.email, u.password_hash, u.role, u.is_active,
              u.company_id, c.name AS company_name, c.onboarding_done
       FROM users u JOIN companies c ON c.id = u.company_id
       WHERE u.email = $1`,
      [email.toLowerCase()]
    );
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    if (!user.is_active) return res.status(403).json({ error: 'Compte désactivé' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });

    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);

    const accessToken  = generateAccessToken(user);
    const refreshToken = generateRefreshToken();
    const expiresAt    = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await pool.query(
      'INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)',
      [user.id, refreshToken, expiresAt]
    );
    return res.json({
      access_token: accessToken, refresh_token: refreshToken,
      user: { id: user.id, email: user.email, role: user.role,
              company_id: user.company_id, company_name: user.company_name,
              onboarding_done: user.onboarding_done },
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// POST /api/auth/refresh
app.post('/api/auth/refresh', async (req, res) => {
  const { refresh_token } = req.body;
  if (!refresh_token) return res.status(400).json({ error: 'Refresh token manquant' });
  try {
    const result = await pool.query(
      `SELECT rt.user_id, rt.expires_at, u.email, u.role, u.company_id, u.is_active
       FROM refresh_tokens rt JOIN users u ON u.id = rt.user_id
       WHERE rt.token = $1`, [refresh_token]
    );
    const row = result.rows[0];
    if (!row) return res.status(401).json({ error: 'Refresh token invalide' });
    if (new Date(row.expires_at) < new Date()) return res.status(401).json({ error: 'Refresh token expiré' });
    if (!row.is_active) return res.status(403).json({ error: 'Compte désactivé' });

    await pool.query('DELETE FROM refresh_tokens WHERE token = $1', [refresh_token]);
    const newAccessToken  = generateAccessToken(row);
    const newRefreshToken = generateRefreshToken();
    const expiresAt       = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await pool.query(
      'INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)',
      [row.user_id, newRefreshToken, expiresAt]
    );
    return res.json({ access_token: newAccessToken, refresh_token: newRefreshToken });
  } catch (err) {
    console.error('Refresh error:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// POST /api/auth/logout
app.post('/api/auth/logout', async (req, res) => {
  const { refresh_token } = req.body;
  if (refresh_token) await pool.query('DELETE FROM refresh_tokens WHERE token = $1', [refresh_token]);
  return res.json({ message: 'Déconnecté' });
});

// GET /api/auth/me
app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.email, u.first_name, u.last_name, u.role, u.company_id,
              c.name AS company_name, c.onboarding_done, c.logo_url,
              c.address, c.phone, c.email AS company_email, c.siret,
              c.default_hourly_rate, c.currency
       FROM users u JOIN companies c ON c.id = u.company_id WHERE u.id = $1`,
      [req.user.id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Utilisateur non trouvé' });
    return res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: 'Erreur serveur' }); }
});

// ============================================================
// ONBOARDING
// ============================================================
app.put('/api/company/onboarding', authenticate, async (req, res) => {
  try {
    const { error, value } = onboardingSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });
    await pool.query(
      `UPDATE companies SET name=$1, email=$2, phone=$3, address=$4,
        siret=$5, tva_number=$6, default_hourly_rate=$7, currency=$8,
        onboarding_done=TRUE, updated_at=NOW() WHERE id=$9`,
      [value.name, value.email, value.phone, value.address,
       value.siret, value.tva_number, value.default_hourly_rate, value.currency,
       req.user.company_id]
    );
    return res.json({ message: 'Paramètres enregistrés', onboarding_done: true });
  } catch (err) {
    console.error('Onboarding error:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// GET /api/company/settings
app.get('/api/company/settings', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, slug, email, phone, address, siret, tva_number,
              default_hourly_rate, currency, logo_url, onboarding_done, plan
       FROM companies WHERE id = $1`, [req.user.company_id]
    );
    return res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: 'Erreur serveur' }); }
});

// PUT /api/company/settings
app.put('/api/company/settings', authenticate, async (req, res) => {
  try {
    const { name, email, phone, address, siret, tva_number, default_hourly_rate, currency } = req.body;
    await pool.query(
      `UPDATE companies SET name=$1, email=$2, phone=$3, address=$4,
        siret=$5, tva_number=$6, default_hourly_rate=$7, currency=$8 WHERE id=$9`,
      [name, email, phone, address, siret, tva_number, default_hourly_rate, currency, req.user.company_id]
    );
    return res.json({ message: 'Paramètres mis à jour' });
  } catch (err) { res.status(500).json({ error: 'Erreur serveur' }); }
});

// ============================================================
// ROUTES CLIENTS
// ============================================================
app.get('/api/clients', authenticate, requireOnboarding, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM clients WHERE company_id = $1 ORDER BY name`, [req.user.company_id]
    );
    return res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Erreur serveur' }); }
});

// ============================================================
// DASHBOARD STATS
// ============================================================
app.get('/api/dashboard/stats', authenticate, requireOnboarding, async (req, res) => {
  try {
    const cid = req.user.company_id;
    const [projects, invoices] = await Promise.all([
      pool.query("SELECT COUNT(*) FROM projects WHERE company_id=$1 AND status='in_progress'", [cid]),
      pool.query(
        `SELECT COALESCE(SUM(total),0) AS revenue FROM invoices
         WHERE company_id=$1 AND status='paid' AND EXTRACT(YEAR FROM issue_date)=EXTRACT(YEAR FROM NOW())`,
        [cid]
      ),
    ]);
    return res.json({
      active_projects:   parseInt(projects.rows[0].count),
      revenue_this_year: parseFloat(invoices.rows[0].revenue),
    });
  } catch (err) { res.status(500).json({ error: 'Erreur serveur' }); }
});

// ============================================================
// MIDDLEWARE ADMIN
// ============================================================
const requireAdmin = async (req, res, next) => {
  try {
    const { rows } = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.user.id]);
    if (!rows[0]?.is_admin) return res.status(403).json({ error: 'Accès admin requis' });
    next();
  } catch (err) { next(err); }
};

// ============================================================
// ROUTES ADMIN
// ============================================================
app.get('/api/admin/stats', authenticate, requireAdmin, async (req, res) => {
  try {
    const [companies, users, activeToday] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM companies WHERE is_active = TRUE'),
      pool.query('SELECT COUNT(*) FROM users WHERE is_active = TRUE'),
      pool.query(`SELECT COUNT(DISTINCT company_id) FROM users WHERE last_login >= NOW() - INTERVAL '24 hours'`),
    ]);
    return res.json({
      total_companies: parseInt(companies.rows[0].count),
      total_users:     parseInt(users.rows[0].count),
      active_today:    parseInt(activeToday.rows[0].count),
    });
  } catch (err) { res.status(500).json({ error: 'Erreur serveur' }); }
});

app.get('/api/admin/companies', authenticate, requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT c.id, c.name, c.email, c.phone, c.slug, c.is_active, c.plan,
             c.onboarding_done, c.created_at,
             COUNT(DISTINCT u.id) AS user_count, MAX(u.last_login) AS last_login
      FROM companies c LEFT JOIN users u ON u.company_id = c.id
      GROUP BY c.id ORDER BY c.created_at DESC
    `);
    return res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Erreur serveur' }); }
});

app.put('/api/admin/company/:id/toggle', authenticate, requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `UPDATE companies SET is_active = NOT is_active, updated_at=NOW()
       WHERE id = $1 RETURNING is_active, name`, [req.params.id]
    );
    return res.json({ message: rows[0].is_active ? `${rows[0].name} activée` : `${rows[0].name} suspendue`, is_active: rows[0].is_active });
  } catch (err) { res.status(500).json({ error: 'Erreur serveur' }); }
});

app.get('/api/admin/me', authenticate, requireAdmin, async (req, res) => {
  return res.json({ is_admin: true, email: req.user.email });
});

// ============================================================
// HEALTH CHECK
// ============================================================
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', db: 'connected', time: new Date().toISOString() });
  } catch (err) {
    res.status(503).json({ status: 'error', db: 'disconnected' });
  }
});

app.get('/', (req, res) => res.json({ status: 'Weldor API running' }));

// ============================================================
// GESTION ERREURS
// ============================================================
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Erreur interne du serveur' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`✅ Weldor API démarré sur le port ${PORT}`));

module.exports = app;
