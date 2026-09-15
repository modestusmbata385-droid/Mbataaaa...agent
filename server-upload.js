require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const { pool, initDb } = require('./db');
const { sendOtpEmail } = require('./mailer');
const { parseQuestionsFromText } = require('./questionParser');
const multer = require('multer');
const mammoth = require('mammoth');
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 8 * 1024 * 1024 } });

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';
const IS_PROD = process.env.NODE_ENV === 'production';
const ALLOWED_PROFILE_TYPES = ['finance', 'business', 'boss', 'driver', 'tenant', 'parent', 'student', 'examiner'];

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

async function logActivity(userId, action, details) {
  try {
    await pool.query('INSERT INTO activity_logs (user_id, action, details) VALUES ($1,$2,$3)', [userId, action, details || null]);
  } catch (e) { console.error('logActivity error:', e.message); }
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
    const inserted = await pool.query(
      'INSERT INTO users (full_name, email, password_hash, is_verified) VALUES ($1,$2,$3,true) RETURNING id',
      [fullName, email.toLowerCase(), hash]
    );

    setAuthCookie(res, inserted.rows[0].id);
    await logActivity(inserted.rows[0].id, 'register', `Amejisajili: ${fullName}`);
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
    await logActivity(user.id, 'login', `Ameingia: ${user.email}`);
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

app.post('/api/auth/logout', requireAuth, async (req, res) => {
  await logActivity(req.user.id, 'logout', `Ametoka: ${req.user.email}`);
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
  await logActivity(req.user.id, 'finance_tx', `${type} TSh ${amount} (${category || '-'})`);
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
  await logActivity(req.user.id, 'business_sale', `${product.name} x${q} = TSh ${total}`);
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
  await logActivity(req.user.id, 'boss_join', `Ameungana na ${asset.asset_type} (${code})`);
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
  await logActivity(req.user.id, 'boss_payment', `Amelipa TSh ${amount} kwa ${conn.asset_type}`);
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

// ===================== ADMIN =====================
const ADMIN_KEY = process.env.ADMIN_KEY || 'mbata2026';
app.get('/api/admin/users', async (req, res) => {
  if (req.query.key !== ADMIN_KEY) return res.status(403).json({ error: 'Huna ruhusa.' });
  const { rows } = await pool.query(
    'SELECT id, full_name, email, is_verified, created_at FROM users ORDER BY created_at DESC'
  );
  res.json({ count: rows.length, users: rows });
});

app.get('/admin', async (req, res) => {
  if (req.query.key !== ADMIN_KEY) return res.status(403).send('Huna ruhusa. Ongeza ?key=... kwenye link.');
  const { rows } = await pool.query(`
    SELECT u.id, u.full_name, u.email, u.is_verified, u.created_at,
      (SELECT created_at FROM activity_logs WHERE user_id=u.id AND action='login' ORDER BY created_at DESC LIMIT 1) AS last_login,
      (SELECT created_at FROM activity_logs WHERE user_id=u.id AND action='logout' ORDER BY created_at DESC LIMIT 1) AS last_logout
    FROM users u ORDER BY u.created_at DESC
  `);
  const logsRes = await pool.query(`
    SELECT l.id, l.action, l.details, l.created_at, u.full_name, u.email
    FROM activity_logs l JOIN users u ON u.id=l.user_id
    ORDER BY l.created_at DESC LIMIT 200
  `);
  const fmt = d => d ? new Date(d).toLocaleString('sw-TZ') : '—';
  const tableRows = rows.map(u => `<tr>
    <td>${u.id}</td>
    <td>${u.full_name}</td>
    <td>${u.email}</td>
    <td>${u.is_verified ? '✅' : '❌'}</td>
    <td>${fmt(u.created_at)}</td>
    <td>${fmt(u.last_login)}</td>
    <td>${fmt(u.last_logout)}</td>
  </tr>`).join('');
  const logRows = logsRes.rows.map(l => `<tr>
    <td>${fmt(l.created_at)}</td>
    <td>${l.full_name}<br><span class="small">${l.email}</span></td>
    <td>${l.action}</td>
    <td>${l.details || ''}</td>
  </tr>`).join('');
  res.send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Mbata Agent - Watumiaji</title>
  <style>
    body{background:#0e1b1a;color:#eaf2ef;font:14px Arial,sans-serif;padding:14px;margin:0}
    h2{margin:24px 0 12px}
    h2:first-child{margin-top:0}
    table{width:100%;border-collapse:collapse;background:#152624;border-radius:8px;overflow:hidden;margin-bottom:10px}
    th,td{padding:9px 7px;border-bottom:1px solid #2a423c;text-align:left;font-size:12.5px}
    th{background:#1d332f;color:#d9a441}
    tr:hover{background:#1d332f}
    .count{color:#8fa89f;margin-bottom:10px}
    .small{color:#8fa89f;font-size:11px}
    .wrap{overflow-x:auto}
  </style></head><body>
  <h2>◆ Watumiaji wa Mbata Agent</h2>
  <p class="count">Jumla: ${rows.length}</p>
  <div class="wrap"><table><tr><th>ID</th><th>Jina</th><th>Email</th><th>Verified</th><th>Alijisajili</th><th>Login ya Mwisho</th><th>Logout ya Mwisho</th></tr>${tableRows}</table></div>
  <h2>📶 Shughuli za Hivi Karibuni (200 za mwisho)</h2>
  <div class="wrap"><table><tr><th>Muda</th><th>Mtumiaji</th><th>Kitendo</th><th>Maelezo</th></tr>${logRows}</table></div>
  </body></html>`);
});

// ===================== EXAMS =====================
app.post('/api/exams', requireAuth, requireProfile('examiner'), async (req, res) => {
  const { title, subject, durationMinutes, startTime, endTime } = req.body;
  if (!title || !(Number(durationMinutes) > 0)) return res.status(400).json({ error: 'Jaza taarifa sahihi.' });
  const r = await pool.query(
    'INSERT INTO exams (examiner_id, title, subject, duration_minutes, start_time, end_time) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id',
    [req.user.id, title, subject || null, durationMinutes, startTime || null, endTime || null]
  );
  res.json({ ok: true, id: r.rows[0].id });
});

app.get('/api/exams', requireAuth, requireProfile('examiner'), async (req, res) => {
  const exams = await pool.query(`
    SELECT e.*, (SELECT COUNT(*) FROM exam_questions q WHERE q.exam_id=e.id) AS question_count,
      (SELECT COUNT(*) FROM exam_attempts a WHERE a.exam_id=e.id) AS attempt_count
    FROM exams e WHERE e.examiner_id=$1 ORDER BY e.created_at DESC
  `, [req.user.id]);
  res.json({ exams: exams.rows });
});

app.post('/api/exams/:id/questions', requireAuth, requireProfile('examiner'), async (req, res) => {
  const examId = req.params.id;
  const own = await pool.query('SELECT id FROM exams WHERE id=$1 AND examiner_id=$2', [examId, req.user.id]);
  if (!own.rows[0]) return res.status(404).json({ error: 'Mtihani haupo.' });
  const { type, questionText, options, correctAnswer, marks } = req.body;
  if (!['mcq', 'true_false'].includes(type)) return res.status(400).json({ error: 'Aina ya swali si sahihi.' });
  if (!questionText || !correctAnswer) return res.status(400).json({ error: 'Jaza swali na jibu sahihi.' });
  const posRes = await pool.query('SELECT COALESCE(MAX(position),0)+1 AS p FROM exam_questions WHERE exam_id=$1', [examId]);
  await pool.query(
    'INSERT INTO exam_questions (exam_id, type, question_text, options, correct_answer, marks, position) VALUES ($1,$2,$3,$4,$5,$6,$7)',
    [examId, type, questionText, JSON.stringify(type === 'true_false' ? ['Kweli', 'Sikweli'] : (options || [])), correctAnswer, marks || 1, posRes.rows[0].p]
  );
  res.json({ ok: true });
});

app.post('/api/exams/:id/questions/bulk', requireAuth, requireProfile('examiner'), async (req, res) => {
  const examId = req.params.id;
  const own = await pool.query('SELECT id FROM exams WHERE id=$1 AND examiner_id=$2', [examId, req.user.id]);
  if (!own.rows[0]) return res.status(404).json({ error: 'Mtihani haupo.' });
  const { questions } = req.body;
  if (!Array.isArray(questions) || !questions.length) return res.status(400).json({ error: 'Hakuna maswali.' });
  let added = 0;
  for (const q of questions) {
    if (!['mcq', 'true_false'].includes(q.type) || !q.questionText || !q.correctAnswer) continue;
    const posRes = await pool.query('SELECT COALESCE(MAX(position),0)+1 AS p FROM exam_questions WHERE exam_id=$1', [examId]);
    await pool.query(
      'INSERT INTO exam_questions (exam_id, type, question_text, options, correct_answer, marks, position) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [examId, q.type, q.questionText, JSON.stringify(q.type === 'true_false' ? ['Kweli', 'Sikweli'] : (q.options || [])), q.correctAnswer, q.marks || 1, posRes.rows[0].p]
    );
    added++;
  }
  res.json({ ok: true, added });
});

app.post('/api/exams/:id/upload-questions', requireAuth, requireProfile('examiner'), upload.single('file'), async (req, res) => {
  try {
    const own = await pool.query('SELECT id FROM exams WHERE id=$1 AND examiner_id=$2', [req.params.id, req.user.id]);
    if (!own.rows[0]) return res.status(404).json({ error: 'Mtihani haupo.' });
    if (!req.file) return res.status(400).json({ error: 'Hakuna faili lililopakiwa.' });

    const { originalname, mimetype, buffer } = req.file;
    const ext = (originalname.split('.').pop() || '').toLowerCase();
    let text = '';

    if (ext === 'txt' || mimetype === 'text/plain') {
      text = buffer.toString('utf8');
    } else if (ext === 'docx' || mimetype.includes('wordprocessingml')) {
      const result = await mammoth.extractRawText({ buffer });
      text = result.value;
    } else if (ext === 'pdf' || mimetype === 'application/pdf') {
      const pdfParse = require('pdf-parse');
      const result = await pdfParse(buffer);
      text = result.text;
    } else if (mimetype.startsWith('image/')) {
      try {
        const Tesseract = require('tesseract.js');
        const result = await Tesseract.recognize(buffer, 'eng');
        text = result.data.text;
      } catch (ocrErr) {
        console.error('OCR error:', ocrErr.message);
        return res.status(500).json({ error: 'Imeshindwa kusoma picha (OCR). Jaribu na document (.docx/.pdf/.txt) badala yake, au andika kwa mkono.' });
      }
    } else {
      return res.status(400).json({ error: 'Aina ya faili haitambuliki. Tumia .txt, .docx, .pdf au picha.' });
    }

    const questions = parseQuestionsFromText(text);
    if (!questions.length) {
      return res.status(400).json({ error: 'Hakuna swali lililotambulika. Hakikisha umefuata muundo sahihi (Q:, A)/B)/C)/D), ANSWER:).', rawText: text.slice(0, 500) });
    }
    res.json({ ok: true, questions, rawTextPreview: text.slice(0, 300) });
  } catch (e) {
    console.error('upload-questions error:', e);
    res.status(500).json({ error: 'Hitilafu wakati wa kusoma faili.' });
  }
});

app.get('/api/exams/:id/questions-admin', requireAuth, requireProfile('examiner'), async (req, res) => {
  const examId = req.params.id;
  const own = await pool.query('SELECT id FROM exams WHERE id=$1 AND examiner_id=$2', [examId, req.user.id]);
  if (!own.rows[0]) return res.status(404).json({ error: 'Mtihani haupo.' });
  const qs = await pool.query('SELECT * FROM exam_questions WHERE exam_id=$1 ORDER BY position', [examId]);
  res.json({ questions: qs.rows });
});

app.post('/api/exams/:id/publish', requireAuth, requireProfile('examiner'), async (req, res) => {
  const r = await pool.query("UPDATE exams SET status='published' WHERE id=$1 AND examiner_id=$2 RETURNING id", [req.params.id, req.user.id]);
  if (!r.rows[0]) return res.status(404).json({ error: 'Mtihani haupo.' });
  res.json({ ok: true });
});

app.get('/api/exams/:id/results', requireAuth, requireProfile('examiner'), async (req, res) => {
  const examId = req.params.id;
  const own = await pool.query('SELECT id, title FROM exams WHERE id=$1 AND examiner_id=$2', [examId, req.user.id]);
  if (!own.rows[0]) return res.status(404).json({ error: 'Mtihani haupo.' });
  const results = await pool.query(
    `SELECT a.*, u.full_name, u.email FROM exam_attempts a JOIN users u ON u.id=a.student_id WHERE a.exam_id=$1 ORDER BY a.started_at DESC`,
    [examId]
  );
  res.json({ exam: own.rows[0], results: results.rows });
});

app.get('/api/exams/available', requireAuth, requireProfile('student'), async (req, res) => {
  const exams = await pool.query(`
    SELECT e.id, e.title, e.subject, e.duration_minutes, e.start_time, e.end_time,
      (SELECT id FROM exam_attempts a WHERE a.exam_id=e.id AND a.student_id=$1) AS attempt_id,
      (SELECT submitted_at FROM exam_attempts a WHERE a.exam_id=e.id AND a.student_id=$1) AS submitted_at
    FROM exams e WHERE e.status='published' ORDER BY e.created_at DESC
  `, [req.user.id]);
  res.json({ exams: exams.rows });
});

app.post('/api/exams/:id/start', requireAuth, requireProfile('student'), async (req, res) => {
  const examId = req.params.id;
  const examRes = await pool.query("SELECT * FROM exams WHERE id=$1 AND status='published'", [examId]);
  const exam = examRes.rows[0];
  if (!exam) return res.status(404).json({ error: 'Mtihani haupo.' });
  const now = new Date();
  if (exam.start_time && now < new Date(exam.start_time)) return res.status(400).json({ error: 'Mtihani bado haujaanza.' });
  if (exam.end_time && now > new Date(exam.end_time)) return res.status(400).json({ error: 'Muda wa mtihani umeisha.' });
  const existing = await pool.query('SELECT * FROM exam_attempts WHERE exam_id=$1 AND student_id=$2', [examId, req.user.id]);
  if (existing.rows[0]) return res.json({ attempt: existing.rows[0] });
  const endsAt = new Date(now.getTime() + exam.duration_minutes * 60000);
  const r = await pool.query('INSERT INTO exam_attempts (exam_id, student_id, ends_at) VALUES ($1,$2,$3) RETURNING *', [examId, req.user.id, endsAt]);
  await logActivity(req.user.id, 'exam_start', `Ameanza mtihani: ${exam.title}`);
  res.json({ attempt: r.rows[0] });
});

app.get('/api/exams/:id/questions', requireAuth, requireProfile('student'), async (req, res) => {
  const examId = req.params.id;
  const attempt = await pool.query('SELECT * FROM exam_attempts WHERE exam_id=$1 AND student_id=$2', [examId, req.user.id]);
  if (!attempt.rows[0]) return res.status(403).json({ error: 'Bado hujaanza mtihani huu.' });
  const qs = await pool.query('SELECT id, type, question_text, options, marks, position FROM exam_questions WHERE exam_id=$1 ORDER BY position', [examId]);
  const answers = await pool.query('SELECT question_id, answer FROM exam_answers WHERE attempt_id=$1', [attempt.rows[0].id]);
  res.json({ attempt: attempt.rows[0], questions: qs.rows, answers: answers.rows });
});

app.post('/api/exams/:id/answer', requireAuth, requireProfile('student'), async (req, res) => {
  const examId = req.params.id;
  const { questionId, answer } = req.body;
  const attempt = await pool.query('SELECT * FROM exam_attempts WHERE exam_id=$1 AND student_id=$2', [examId, req.user.id]);
  if (!attempt.rows[0] || attempt.rows[0].submitted_at) return res.status(403).json({ error: 'Huwezi kujibu sasa.' });
  await pool.query(
    `INSERT INTO exam_answers (attempt_id, question_id, answer) VALUES ($1,$2,$3)
     ON CONFLICT (attempt_id, question_id) DO UPDATE SET answer=$3`,
    [attempt.rows[0].id, questionId, String(answer)]
  );
  res.json({ ok: true });
});

async function gradeAttempt(examId, attemptId) {
  const qs = await pool.query('SELECT * FROM exam_questions WHERE exam_id=$1', [examId]);
  const ansRows = await pool.query('SELECT * FROM exam_answers WHERE attempt_id=$1', [attemptId]);
  const ansMap = {}; ansRows.rows.forEach(a => ansMap[a.question_id] = a.answer);
  let score = 0, total = 0;
  for (const q of qs.rows) {
    total += Number(q.marks);
    const given = (ansMap[q.id] || '').trim().toLowerCase();
    const correct = (q.correct_answer || '').trim().toLowerCase();
    const isCorrect = !!given && given === correct;
    if (isCorrect) score += Number(q.marks);
    await pool.query(
      `INSERT INTO exam_answers (attempt_id, question_id, answer, is_correct, marks_awarded) VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (attempt_id, question_id) DO UPDATE SET is_correct=$4, marks_awarded=$5`,
      [attemptId, q.id, ansMap[q.id] || null, isCorrect, isCorrect ? q.marks : 0]
    );
  }
  await pool.query('UPDATE exam_attempts SET submitted_at=now(), score=$1, total_marks=$2 WHERE id=$3', [score, total, attemptId]);
  return { score, total };
}

app.post('/api/exams/:id/submit', requireAuth, requireProfile('student'), async (req, res) => {
  const examId = req.params.id;
  const attempt = await pool.query('SELECT * FROM exam_attempts WHERE exam_id=$1 AND student_id=$2', [examId, req.user.id]);
  const att = attempt.rows[0];
  if (!att) return res.status(404).json({ error: 'Hujaanza mtihani.' });
  if (att.submitted_at) return res.json({ ok: true, already: true, score: att.score, total: att.total_marks });
  const { score, total } = await gradeAttempt(examId, att.id);
  await logActivity(req.user.id, 'exam_submit', `Amemaliza mtihani #${examId}: ${score}/${total}`);
  res.json({ ok: true, score, total });
});

app.get('/api/exams/:id/result', requireAuth, requireProfile('student'), async (req, res) => {
  const attempt = await pool.query('SELECT * FROM exam_attempts WHERE exam_id=$1 AND student_id=$2', [req.params.id, req.user.id]);
  if (!attempt.rows[0]) return res.status(404).json({ error: 'Hakuna taarifa.' });
  res.json({ attempt: attempt.rows[0] });
});

// Muda/status ya sasa ya attempt (kwa polling ya mwanafunzi)
app.get('/api/exams/:id/attempt-status', requireAuth, requireProfile('student'), async (req, res) => {
  const attempt = await pool.query('SELECT ends_at, paused_at, submitted_at, score, total_marks FROM exam_attempts WHERE exam_id=$1 AND student_id=$2', [req.params.id, req.user.id]);
  if (!attempt.rows[0]) return res.status(404).json({ error: 'Hakuna attempt.' });
  res.json({ attempt: attempt.rows[0] });
});

// Ripoti "kutoka nje ya mtihani" (tab-switch / kubadili app)
app.post('/api/exams/:id/violation', requireAuth, requireProfile('student'), async (req, res) => {
  const r = await pool.query(
    'UPDATE exam_attempts SET violation_count = violation_count + 1 WHERE exam_id=$1 AND student_id=$2 AND submitted_at IS NULL RETURNING violation_count',
    [req.params.id, req.user.id]
  );
  if (r.rows[0]) await logActivity(req.user.id, 'exam_violation', `Ametoka nje ya mtihani #${req.params.id} (jumla: ${r.rows[0].violation_count})`);
  res.json({ ok: true });
});

// ---------- LIVE CONTROL (Examiner) ----------
app.get('/api/exams/:id/live', requireAuth, requireProfile('examiner'), async (req, res) => {
  const examId = req.params.id;
  const own = await pool.query('SELECT id, title FROM exams WHERE id=$1 AND examiner_id=$2', [examId, req.user.id]);
  if (!own.rows[0]) return res.status(404).json({ error: 'Mtihani haupo.' });
  const totalQ = await pool.query('SELECT COUNT(*) AS c FROM exam_questions WHERE exam_id=$1', [examId]);
  const attempts = await pool.query(`
    SELECT a.*, u.full_name, u.email,
      (SELECT COUNT(*) FROM exam_answers x WHERE x.attempt_id=a.id) AS answered_count
    FROM exam_attempts a JOIN users u ON u.id=a.student_id
    WHERE a.exam_id=$1 ORDER BY a.started_at DESC
  `, [examId]);
  res.json({ exam: own.rows[0], totalQuestions: Number(totalQ.rows[0].c), attempts: attempts.rows });
});

async function getOwnAttempt(examId, attemptId, examinerId) {
  const r = await pool.query(
    `SELECT a.* FROM exam_attempts a JOIN exams e ON e.id=a.exam_id WHERE a.id=$1 AND a.exam_id=$2 AND e.examiner_id=$3`,
    [attemptId, examId, examinerId]
  );
  return r.rows[0];
}

app.post('/api/exams/:id/attempts/:attemptId/extend', requireAuth, requireProfile('examiner'), async (req, res) => {
  const att = await getOwnAttempt(req.params.id, req.params.attemptId, req.user.id);
  if (!att) return res.status(404).json({ error: 'Attempt haipo.' });
  if (att.submitted_at) return res.status(400).json({ error: 'Mwanafunzi tayari amemaliza.' });
  const minutes = Number(req.body.minutes || 5);
  if (att.paused_at) {
    await pool.query('UPDATE exam_attempts SET paused_remaining_seconds = paused_remaining_seconds + $1 WHERE id=$2', [minutes * 60, att.id]);
  } else {
    await pool.query("UPDATE exam_attempts SET ends_at = ends_at + ($1 || ' minutes')::interval WHERE id=$2", [minutes, att.id]);
  }
  await logActivity(req.user.id, 'exam_extend', `Ameongeza dakika ${minutes} kwa attempt #${att.id}`);
  res.json({ ok: true });
});

app.post('/api/exams/:id/attempts/:attemptId/pause', requireAuth, requireProfile('examiner'), async (req, res) => {
  const att = await getOwnAttempt(req.params.id, req.params.attemptId, req.user.id);
  if (!att) return res.status(404).json({ error: 'Attempt haipo.' });
  if (att.submitted_at || att.paused_at) return res.status(400).json({ error: 'Haiwezekani sasa.' });
  const remaining = Math.max(0, Math.floor((new Date(att.ends_at) - new Date()) / 1000));
  await pool.query('UPDATE exam_attempts SET paused_at=now(), paused_remaining_seconds=$1 WHERE id=$2', [remaining, att.id]);
  await logActivity(req.user.id, 'exam_pause', `Amesimamisha attempt #${att.id}`);
  res.json({ ok: true });
});

app.post('/api/exams/:id/attempts/:attemptId/resume', requireAuth, requireProfile('examiner'), async (req, res) => {
  const att = await getOwnAttempt(req.params.id, req.params.attemptId, req.user.id);
  if (!att) return res.status(404).json({ error: 'Attempt haipo.' });
  if (!att.paused_at) return res.status(400).json({ error: 'Haijasimamishwa.' });
  await pool.query(
    "UPDATE exam_attempts SET ends_at = now() + (paused_remaining_seconds || ' seconds')::interval, paused_at=NULL, paused_remaining_seconds=NULL WHERE id=$1",
    [att.id]
  );
  await logActivity(req.user.id, 'exam_resume', `Ameendeleza attempt #${att.id}`);
  res.json({ ok: true });
});

app.post('/api/exams/:id/attempts/:attemptId/end', requireAuth, requireProfile('examiner'), async (req, res) => {
  const att = await getOwnAttempt(req.params.id, req.params.attemptId, req.user.id);
  if (!att) return res.status(404).json({ error: 'Attempt haipo.' });
  if (att.submitted_at) return res.json({ ok: true, already: true });
  const { score, total } = await gradeAttempt(req.params.id, att.id);
  await logActivity(req.user.id, 'exam_force_end', `Amemaliza kwa nguvu attempt #${att.id}: ${score}/${total}`);
  res.json({ ok: true, score, total });
});

app.post('/api/exams/:id/attempts/:attemptId/reset', requireAuth, requireProfile('examiner'), async (req, res) => {
  const att = await getOwnAttempt(req.params.id, req.params.attemptId, req.user.id);
  if (!att) return res.status(404).json({ error: 'Attempt haipo.' });
  await pool.query('DELETE FROM exam_attempts WHERE id=$1', [att.id]);
  await logActivity(req.user.id, 'exam_reset', `Ame-reset attempt #${att.id}`);
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
