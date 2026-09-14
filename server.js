require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const { pool, initDb } = require('./db');
const { sendOtpEmail } = require('./mailer');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';
const IS_PROD = process.env.NODE_ENV === 'production';
const ALLOWED_PROFILE_TYPES = ['finance', 'business', 'boss', 'driver', 'tenant', 'parent', 'student'];

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Helpers ----------
function genOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function genCode(prefix) {
  return `${prefix}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
}

function setAuthCookie(res, userId) {
  const token = jwt.sign({ uid: userId }, JWT_SECRET, { expiresIn: '30d' });
  res.cookie('token', token, {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000
  });
}

async function requireAuth(req, res, next) {
  try {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Haujaingia.' });
    const payload = jwt.verify(token, JWT_SECRET);
    const { rows } = await pool.query('SELECT id, full_name, email, is_verified FROM users WHERE id=$1', [payload.uid]);
    if (!rows[0]) return res.status(401).json({ error: 'Haujaingia.' });
    req.user = rows[0];
    next();
  } catch {
    res.status(401).json({ error: 'Haujaingia.' });
  }
}

async function userHasProfile(userId, type) {
  const { rows } = await pool.query('SELECT 1 FROM profiles WHERE user_id=$1 AND type=$2', [userId, type]);
  return rows.length > 0;
}

function requireProfile(type) {
  return async (req, res, next) => {
    if (!(await userHasProfile(req.user.id, type))) {
      return res.status(403).json({ error: `Unahitaji profile ya ${type} kwanza.` });
    }
    next();
  };
}

// ===================== AUTH =====================
app.post('/api/auth/register', async (req, res) => {
  try {
    const { fullName, email, password } = req.body;
    if (!fullName || !email || !password) return res.status(400).json({ error: 'Jaza taarifa zote.' });
    if (password.length < 6) return res.status(400).json({ error: 'Password iwe angalau herufi 6.' });

    const existing = await pool.query('SELECT id FROM users WHERE email=$1', [email.toLowerCase()]);
    if (existing.rows.length) return res.status(400).json({ error: 'Email tayari imesajiliwa.' });

    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (full_name, email, password_hash) VALUES ($1,$2,$3)',
      [fullName, email.toLowerCase(), hash]
    );

    const code = genOtp();
    await pool.query(
      "INSERT INTO otp_codes (email, code, purpose, expires_at) VALUES ($1,$2,'verify', now() + interval '10 minutes')",
      [email.toLowerCase(), code]
    );
    await sendOtpEmail(email.toLowerCase(), code, 'verify');

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Hitilafu ya server.' });
  }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, code } = req.body;
    const { rows } = await pool.query(
      `SELECT * FROM otp_codes WHERE email=$1 AND code=$2 AND purpose='verify' AND used=false AND expires_at > now()
       ORDER BY id DESC LIMIT 1`,
      [String(email).toLowerCase(), code]
    );
    if (!rows[0]) return res.status(400).json({ error: 'OTP si sahihi au imeisha muda.' });

    await pool.query('UPDATE otp_codes SET used=true WHERE id=$1', [rows[0].id]);
    const userRes = await pool.query(
      'UPDATE users SET is_verified=true WHERE email=$1 RETURNING id',
      [String(email).toLowerCase()]
    );
    if (!userRes.rows[0]) return res.status(400).json({ error: 'Akaunti haipo.' });

    setAuthCookie(res, userRes.rows[0].id);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Hitilafu ya server.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [String(email || '').toLowerCase()]);
    const user = rows[0];
    if (!user) return res.status(400).json({ error: 'Email au password si sahihi.' });

    const match = await bcrypt.compare(password || '', user.password_hash);
    if (!match) return res.status(400).json({ error: 'Email au password si sahihi.' });
    if (!user.is_verified) return res.status(400).json({ error: 'Thibitisha email yako kwanza (OTP).' });

    setAuthCookie(res, user.id);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Hitilafu ya server.' });
  }
});

app.post('/api/auth/forgot', async (req, res) => {
  try {
    const { email } = req.body;
    const { rows } = await pool.query('SELECT id FROM users WHERE email=$1', [String(email || '').toLowerCase()]);
    if (rows[0]) {
      const code = genOtp();
      await pool.query(
        "INSERT INTO otp_codes (email, code, purpose, expires_at) VALUES ($1,$2,'reset', now() + interval '10 minutes')",
        [String(email).toLowerCase(), code]
      );
      await sendOtpEmail(String(email).toLowerCase(), code, 'reset');
    }
    // Jibu moja tu bila kujali akaunti ipo au la (kulinda usiri)
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Hitilafu ya server.' });
  }
});

app.post('/api/auth/reset', async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;
    if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Password iwe angalau herufi 6.' });

    const { rows } = await pool.query(
      `SELECT * FROM otp_codes WHERE email=$1 AND code=$2 AND purpose='reset' AND used=false AND expires_at > now()
       ORDER BY id DESC LIMIT 1`,
      [String(email).toLowerCase(), code]
    );
    if (!rows[0]) return res.status(400).json({ error: 'OTP si sahihi au imeisha muda.' });

    await pool.query('UPDATE otp_codes SET used=true WHERE id=$1', [rows[0].id]);
    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password_hash=$1 WHERE email=$2', [hash, String(email).toLowerCase()]);

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Hitilafu ya server.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// ===================== PROFILES =====================
app.get('/api/profiles', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT type FROM profiles WHERE user_id=$1', [req.user.id]);
  res.json({ profiles: rows.map(r => r.type) });
});

app.post('/api/profiles', requireAuth, async (req, res) => {
  const { type } = req.body;
  if (!ALLOWED_PROFILE_TYPES.includes(type)) return res.status(400).json({ error: 'Aina ya profile si sahihi.' });
  await pool.query(
    'INSERT INTO profiles (user_id, type) VALUES ($1,$2) ON CONFLICT (user_id, type) DO NOTHING',
    [req.user.id, type]
  );
  res.json({ ok: true });
});

// ===================== FINANCE =====================
app.get('/api/finance', requireAuth, requireProfile('finance'), async (req, res) => {
  const tx = await pool.query(
    'SELECT * FROM finance_transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 200',
    [req.user.id]
  );
  const income = tx.rows.filter(t => t.type === 'income').reduce((s, t) => s + Number(t.amount), 0);
  const expense = tx.rows.filter(t => t.type === 'expense').reduce((s, t) => s + Number(t.amount), 0);
  res.json({ balance: income - expense, income, expense, transactions: tx.rows });
});

app.post('/api/finance/transactions', requireAuth, requireProfile('finance'), async (req, res) => {
  const { type, amount, category, note } = req.body;
  if (!['income', 'expense'].includes(type)) return res.status(400).json({ error: 'Aina si sahihi.' });
  if (!(Number(amount) > 0)) return res.status(400).json({ error: 'Kiasi si sahihi.' });
  await pool.query(
    'INSERT INTO finance_transactions (user_id, type, amount, category, note) VALUES ($1,$2,$3,$4,$5)',
    [req.user.id, type, amount, category || null, note || null]
  );
  res.json({ ok: true });
});

app.post('/api/finance/goals', requireAuth, requireProfile('finance'), async (req, res) => {
  const { title, target } = req.body;
  if (!title || !(Number(target) > 0)) return res.status(400).json({ error: 'Jaza taarifa sahihi.' });
  await pool.query('INSERT INTO finance_goals (user_id, title, target) VALUES ($1,$2,$3)', [req.user.id, title, target]);
  res.json({ ok: true });
});

// ===================== BUSINESS =====================
app.get('/api/business', requireAuth, requireProfile('business'), async (req, res) => {
  const products = await pool.query('SELECT * FROM business_products WHERE user_id=$1 ORDER BY created_at DESC', [req.user.id]);
  const sales = await pool.query('SELECT * FROM business_sales WHERE user_id=$1 ORDER BY created_at DESC LIMIT 200', [req.user.id]);
  const customers = await pool.query('SELECT * FROM business_customers WHERE user_id=$1 ORDER BY created_at DESC', [req.user.id]);
  const expenses = await pool.query('SELECT * FROM business_expenses WHERE user_id=$1 ORDER BY created_at DESC', [req.user.id]);

  const revenue = sales.rows.reduce((s, r) => s + Number(r.total), 0);
  const cogs = sales.rows.reduce((s, r) => s + Number(r.buy_price) * Number(r.qty), 0);
  const totalExpenses = expenses.rows.reduce((s, r) => s + Number(r.amount), 0);
  const netProfit = revenue - cogs - totalExpenses;

  res.json({
    revenue,
    netProfit,
    products: products.rows,
    sales: sales.rows,
    customers: customers.rows,
    expenses: expenses.rows
  });
});

app.post('/api/business/products', requireAuth, requireProfile('business'), async (req, res) => {
  const { name, buyPrice, sellPrice, stock, minStock } = req.body;
  if (!name) return res.status(400).json({ error: 'Weka jina la bidhaa.' });
  await pool.query(
    'INSERT INTO business_products (user_id, name, buy_price, sell_price, stock, min_stock) VALUES ($1,$2,$3,$4,$5,$6)',
    [req.user.id, name, buyPrice || 0, sellPrice || 0, stock || 0, minStock || 0]
  );
  res.json({ ok: true });
});

app.post('/api/business/sales', requireAuth, requireProfile('business'), async (req, res) => {
  const { productId, qty } = req.body;
  const q = Number(qty);
  if (!(q > 0)) return res.status(400).json({ error: 'Idadi si sahihi.' });

  const { rows } = await pool.query('SELECT * FROM business_products WHERE id=$1 AND user_id=$2', [productId, req.user.id]);
  const product = rows[0];
  if (!product) return res.status(404).json({ error: 'Bidhaa haipo.' });
  if (product.stock < q) return res.status(400).json({ error: 'Stock haitoshi.' });

  const total = q * Number(product.sell_price);
  await pool.query('BEGIN');
  try {
    await pool.query('UPDATE business_products SET stock = stock - $1 WHERE id=$2', [q, product.id]);
    await pool.query(
      'INSERT INTO business_sales (user_id, product_id, qty, buy_price, sell_price, total) VALUES ($1,$2,$3,$4,$5,$6)',
      [req.user.id, product.id, q, product.buy_price, product.sell_price, total]
    );
    await pool.query('COMMIT');
  } catch (e) {
    await pool.query('ROLLBACK');
    throw e;
  }
  res.json({ ok: true });
});

app.post('/api/business/customers', requireAuth, requireProfile('business'), async (req, res) => {
  const { name, phone } = req.body;
  if (!name) return res.status(400).json({ error: 'Weka jina la mteja.' });
  await pool.query('INSERT INTO business_customers (user_id, name, phone) VALUES ($1,$2,$3)', [req.user.id, name, phone || null]);
  res.json({ ok: true });
});

app.post('/api/business/expenses', requireAuth, requireProfile('business'), async (req, res) => {
  const { category, amount, note } = req.body;
  if (!(Number(amount) > 0)) return res.status(400).json({ error: 'Kiasi si sahihi.' });
  await pool.query('INSERT INTO business_expenses (user_id, category, amount, note) VALUES ($1,$2,$3,$4)', [req.user.id, category || null, amount, note || null]);
  res.json({ ok: true });
});

// ===================== BOSS CONNECT =====================
app.get('/api/boss-connect', requireAuth, async (req, res) => {
  const assets = await pool.query('SELECT * FROM boss_assets WHERE boss_user_id=$1 ORDER BY created_at DESC', [req.user.id]);
  const connections = await pool.query(
    `SELECT c.*, a.asset_type, a.required_amount, a.frequency
     FROM boss_connections c JOIN boss_assets a ON a.id=c.asset_id
     WHERE c.role_user_id=$1 ORDER BY c.created_at DESC`,
    [req.user.id]
  );
  res.json({ assets: assets.rows, connections: connections.rows });
});

app.post('/api/boss-connect/assets', requireAuth, requireProfile('boss'), async (req, res) => {
  const { assetType, requiredAmount, frequency } = req.body;
  if (!['motorcycle', 'property'].includes(assetType)) return res.status(400).json({ error: 'Aina ya asset si sahihi.' });
  if (!['daily', 'weekly', 'monthly'].includes(frequency)) return res.status(400).json({ error: 'Frequency si sahihi.' });
  if (!(Number(requiredAmount) > 0)) return res.status(400).json({ error: 'Kiasi si sahihi.' });

  let code;
  for (let i = 0; i < 5; i++) {
    code = genCode('MB-BOSS');
    const exists = await pool.query('SELECT 1 FROM boss_assets WHERE code=$1', [code]);
    if (!exists.rows.length) break;
  }

  await pool.query(
    'INSERT INTO boss_assets (boss_user_id, asset_type, required_amount, frequency, code) VALUES ($1,$2,$3,$4,$5)',
    [req.user.id, assetType, requiredAmount, frequency, code]
  );
  res.json({ ok: true, code });
});

app.post('/api/boss-connect/join', requireAuth, async (req, res) => {
  const { code, roleType } = req.body;
  if (!['driver', 'tenant'].includes(roleType)) return res.status(400).json({ error: 'Aina si sahihi.' });
  if (!(await userHasProfile(req.user.id, roleType))) {
    return res.status(403).json({ error: `Unahitaji profile ya ${roleType} kwanza.` });
  }

  const { rows } = await pool.query('SELECT * FROM boss_assets WHERE code=$1', [String(code || '').toUpperCase()]);
  const asset = rows[0];
  if (!asset) return res.status(404).json({ error: 'Code si sahihi.' });

  await pool.query(
    'INSERT INTO boss_connections (asset_id, role_user_id, role_type, status) VALUES ($1,$2,$3,$4)',
    [asset.id, req.user.id, roleType, 'active']
  );
  await pool.query(
    'INSERT INTO notifications (user_id, title, body) VALUES ($1,$2,$3)',
    [asset.boss_user_id, 'Muunganisho mpya', `Mtu mpya ameungana na asset yako (${asset.asset_type}).`]
  );
  res.json({ ok: true });
});

app.post('/api/boss-connect/payments', requireAuth, async (req, res) => {
  const { connectionId, amount, method } = req.body;
  if (!(Number(amount) > 0)) return res.status(400).json({ error: 'Kiasi si sahihi.' });

  const { rows } = await pool.query(
    `SELECT c.*, a.boss_user_id, a.asset_type FROM boss_connections c
     JOIN boss_assets a ON a.id=c.asset_id
     WHERE c.id=$1 AND c.role_user_id=$2 AND c.status='active'`,
    [connectionId, req.user.id]
  );
  const conn = rows[0];
  if (!conn) return res.status(404).json({ error: 'Muunganisho haupo au haujaidhinishwa.' });

  await pool.query('INSERT INTO boss_payments (connection_id, amount, method) VALUES ($1,$2,$3)', [connectionId, amount, method || null]);
  await pool.query(
    'INSERT INTO notifications (user_id, title, body) VALUES ($1,$2,$3)',
    [conn.boss_user_id, 'Malipo mapya', `Malipo ya TSh ${amount} yamepokelewa kwa ${conn.asset_type}.`]
  );
  res.json({ ok: true });
});

// ===================== EDUCATION =====================
app.get('/api/education', requireAuth, async (req, res) => {
  const links = await pool.query(
    `SELECT s.full_name, s.email, es.school_name, es.class_name
     FROM education_parent_links l
     JOIN users s ON s.id = l.student_user_id
     LEFT JOIN education_students es ON es.user_id = s.id
     WHERE l.parent_user_id = $1 ORDER BY l.created_at DESC`,
    [req.user.id]
  );
  res.json({ links: links.rows });
});

app.post('/api/education/link-parent', requireAuth, requireProfile('parent'), async (req, res) => {
  const { studentEmail } = req.body;
  const { rows } = await pool.query('SELECT id FROM users WHERE email=$1', [String(studentEmail || '').toLowerCase()]);
  const student = rows[0];
  if (!student) return res.status(404).json({ error: 'Mwanafunzi hapatikani.' });
  if (!(await userHasProfile(student.id, 'student'))) return res.status(400).json({ error: 'Akaunti hiyo si ya mwanafunzi.' });

  await pool.query(
    'INSERT INTO education_parent_links (parent_user_id, student_user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
    [req.user.id, student.id]
  );
  res.json({ ok: true });
});

app.post('/api/education/student', requireAuth, requireProfile('student'), async (req, res) => {
  const { studentNumber, schoolName, className } = req.body;
  await pool.query(
    `INSERT INTO education_students (user_id, student_number, school_name, class_name)
     VALUES ($1,$2,$3,$4)
     ON CONFLICT (user_id) DO UPDATE SET student_number=$2, school_name=$3, class_name=$4`,
    [req.user.id, studentNumber || null, schoolName || null, className || null]
  );
  res.json({ ok: true });
});

app.post('/api/education/results', requireAuth, requireProfile('student'), async (req, res) => {
  const { subject, score, maxScore, term } = req.body;
  if (!subject || score === undefined) return res.status(400).json({ error: 'Jaza taarifa zote.' });
  await pool.query(
    'INSERT INTO education_results (student_user_id, subject, score, max_score, term) VALUES ($1,$2,$3,$4,$5)',
    [req.user.id, subject, score, maxScore || 100, term || null]
  );
  res.json({ ok: true });
});

app.post('/api/education/attendance', requireAuth, requireProfile('student'), async (req, res) => {
  const { present } = req.body;
  await pool.query('INSERT INTO education_attendance (student_user_id, present) VALUES ($1,$2)', [req.user.id, !!present]);
  res.json({ ok: true });
});

// ===================== NOTIFICATIONS =====================
app.get('/api/notifications', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100', [req.user.id]);
  res.json({ notifications: rows });
});

// ---------- Fallback: serve frontend for any other route ----------
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ---------- Start ----------
initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`Mbata Agent inaendesha kwenye port ${PORT}`));
  })
  .catch(err => {
    console.error('Imeshindwa kuunganisha database:', err);
    process.exit(1);
  });
      
