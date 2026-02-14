const { Pool } = require("pg");
const bcrypt   = require("bcryptjs");

if (!process.env.DATABASE_URL) {
  console.error("❌ DATABASE_URL is not set!");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ── Query helpers ─────────────────────────────────────────────────────────────
const run = async (sql, params = []) => {
  const client = await pool.connect();
  try {
    return await client.query(sql, params);
  } finally {
    client.release();
  }
};

const all = async (sql, params = []) => {
  const res = await run(sql, params);
  return res.rows;
};

const get = async (sql, params = []) => {
  const rows = await all(sql, params);
  return rows[0] || null;
};

// ── Init ──────────────────────────────────────────────────────────────────────
const ready = (async () => {
  console.log("🔌 Connecting to PostgreSQL...");
  console.log("📋 DATABASE_URL defined:", !!process.env.DATABASE_URL);

  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id         SERIAL PRIMARY KEY,
      username   TEXT UNIQUE NOT NULL,
      password   TEXT NOT NULL,
      sec_q      INTEGER NOT NULL DEFAULT 0,
      sec_a      TEXT NOT NULL DEFAULT '',
      is_admin   INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT to_char(now(), 'YYYY-MM-DD HH24:MI:SS')
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS entries (
      id          SERIAL PRIMARY KEY,
      user_id     INTEGER NOT NULL,
      date        TEXT NOT NULL,
      bed_time    TEXT NOT NULL,
      wake_time   TEXT NOT NULL,
      duration    REAL NOT NULL,
      screen_time REAL NOT NULL,
      energy      INTEGER NOT NULL,
      notes       TEXT DEFAULT '',
      created_at  TEXT NOT NULL DEFAULT to_char(now(), 'YYYY-MM-DD HH24:MI:SS'),
      UNIQUE(user_id, date)
    )
  `);

  const admin = await get("SELECT id FROM users WHERE username = 'admin'");
  if (!admin) {
    const hash = bcrypt.hashSync("admin123", 10);
    await run(
      "INSERT INTO users (username, password, is_admin) VALUES ($1, $2, 1)",
      ["admin", hash]
    );
    console.log("✅ Admin account created.");
  }

  console.log("✅ PostgreSQL database ready.");
  return { run, all, get };
})();

module.exports = { ready };
