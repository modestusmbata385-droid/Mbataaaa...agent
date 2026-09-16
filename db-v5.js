const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('localhost')
    ? false
    : { rejectUnauthorized: false }
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      full_name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      is_verified BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS otp_codes (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL,
      code TEXT NOT NULL,
      purpose TEXT NOT NULL,
      used BOOLEAN NOT NULL DEFAULT FALSE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS profiles (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(user_id, type)
    );

    CREATE TABLE IF NOT EXISTS finance_transactions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      amount NUMERIC NOT NULL,
      category TEXT,
      note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS finance_goals (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      target NUMERIC NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS business_products (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      buy_price NUMERIC NOT NULL DEFAULT 0,
      sell_price NUMERIC NOT NULL DEFAULT 0,
      stock INTEGER NOT NULL DEFAULT 0,
      min_stock INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS business_sales (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      product_id INTEGER NOT NULL REFERENCES business_products(id) ON DELETE CASCADE,
      qty INTEGER NOT NULL,
      buy_price NUMERIC NOT NULL,
      sell_price NUMERIC NOT NULL,
      total NUMERIC NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS business_customers (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      phone TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS business_expenses (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      category TEXT,
      amount NUMERIC NOT NULL,
      note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS boss_assets (
      id SERIAL PRIMARY KEY,
      boss_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      asset_type TEXT NOT NULL,
      required_amount NUMERIC NOT NULL,
      frequency TEXT NOT NULL,
      code TEXT UNIQUE NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS boss_connections (
      id SERIAL PRIMARY KEY,
      asset_id INTEGER NOT NULL REFERENCES boss_assets(id) ON DELETE CASCADE,
      role_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      role_type TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS boss_payments (
      id SERIAL PRIMARY KEY,
      connection_id INTEGER NOT NULL REFERENCES boss_connections(id) ON DELETE CASCADE,
      amount NUMERIC NOT NULL,
      method TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS education_students (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      student_number TEXT,
      school_name TEXT,
      class_name TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS education_parent_links (
      id SERIAL PRIMARY KEY,
      parent_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      student_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      UNIQUE(parent_user_id, student_user_id)
    );

    CREATE TABLE IF NOT EXISTS education_results (
      id SERIAL PRIMARY KEY,
      student_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      subject TEXT NOT NULL,
      score NUMERIC NOT NULL,
      max_score NUMERIC NOT NULL DEFAULT 100,
      term TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS education_attendance (
      id SERIAL PRIMARY KEY,
      student_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      present BOOLEAN NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS activity_logs (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      action TEXT NOT NULL,
      details TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS exams (
      id SERIAL PRIMARY KEY,
      examiner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      subject TEXT,
      duration_minutes INTEGER NOT NULL,
      start_time TIMESTAMPTZ,
      end_time TIMESTAMPTZ,
      status TEXT NOT NULL DEFAULT 'draft',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS exam_questions (
      id SERIAL PRIMARY KEY,
      exam_id INTEGER NOT NULL REFERENCES exams(id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      question_text TEXT NOT NULL,
      options JSONB,
      correct_answer TEXT NOT NULL,
      marks NUMERIC NOT NULL DEFAULT 1,
      position INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS exam_attempts (
      id SERIAL PRIMARY KEY,
      exam_id INTEGER NOT NULL REFERENCES exams(id) ON DELETE CASCADE,
      student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      ends_at TIMESTAMPTZ NOT NULL,
      submitted_at TIMESTAMPTZ,
      score NUMERIC,
      total_marks NUMERIC,
      paused_at TIMESTAMPTZ,
      paused_remaining_seconds INTEGER,
      violation_count INTEGER NOT NULL DEFAULT 0,
      UNIQUE(exam_id, student_id)
    );
    ALTER TABLE exam_attempts ADD COLUMN IF NOT EXISTS paused_at TIMESTAMPTZ;
    ALTER TABLE exam_attempts ADD COLUMN IF NOT EXISTS paused_remaining_seconds INTEGER;
    ALTER TABLE exam_attempts ADD COLUMN IF NOT EXISTS violation_count INTEGER NOT NULL DEFAULT 0;

    CREATE TABLE IF NOT EXISTS exam_answers (
      id SERIAL PRIMARY KEY,
      attempt_id INTEGER NOT NULL REFERENCES exam_attempts(id) ON DELETE CASCADE,
      question_id INTEGER NOT NULL REFERENCES exam_questions(id) ON DELETE CASCADE,
      answer TEXT,
      is_correct BOOLEAN,
      marks_awarded NUMERIC,
      answer_file_name TEXT,
      answer_file_mimetype TEXT,
      answer_file_data TEXT,
      graded_at TIMESTAMPTZ,
      UNIQUE(attempt_id, question_id)
    );
    ALTER TABLE exam_answers ADD COLUMN IF NOT EXISTS answer_file_name TEXT;
    ALTER TABLE exam_answers ADD COLUMN IF NOT EXISTS answer_file_mimetype TEXT;
    ALTER TABLE exam_answers ADD COLUMN IF NOT EXISTS answer_file_data TEXT;
    ALTER TABLE exam_answers ADD COLUMN IF NOT EXISTS graded_at TIMESTAMPTZ;
    ALTER TABLE exam_questions ALTER COLUMN correct_answer DROP NOT NULL;

    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      body TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
}

module.exports = { pool, initDb };
