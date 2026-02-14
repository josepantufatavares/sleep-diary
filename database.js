const { createClient } = require("@libsql/client");
const bcrypt = require("bcryptjs");

// ── Turso client ──────────────────────────────────────────────────────────────
const db = createClient({
  url:       process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

// ── Query helpers ─────────────────────────────────────────────────────────────

// Run a write query (INSERT, UPDATE, DELETE, CREATE)
const run = async (sql, params = []) => {
  try {
    return await db.execute({ sql, args: params });
  } catch (e) {
    console.error("❌ DB run() error:", e.message, sql);
    throw e;
  }
};

// Return array of row objects
const all = async (sql, params = []) => {
  try {
    const res = await db.execute({ sql, args: params });
    return res.rows;
  } catch (e) {
    console.error("❌ DB all() error:", e.message, sql);
    throw e;
  }
};

// Return single row object
const get = async (sql, params = []) => {
  const rows = await all(sql, params);
  return rows[0] || null;
};

// ── Init: create tables + seed admin ─────────────────────────────────────────
const ready = (async () => {
  console.log("🔌 Connecting to Turso...");

  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      username   TEXT UNIQUE NOT NULL,
      password   TEXT NOT NULL,
      sec_q      INTEGER NOT NULL DEFAULT 0,
      sec_a      TEXT NOT NULL DEFAULT '',
      is_admin   INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS entries (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id     INTEGER NOT NULL,
      date        TEXT NOT NULL,
      bed_time    TEXT NOT NULL,
      wake_time   TEXT NOT NULL,
      duration    REAL NOT NULL,
      screen_time REAL NOT NULL,
      energy      INTEGER NOT NULL,
      notes       TEXT DEFAULT '',
      created_at  TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(user_id, date)
    )
  `);

  // Seed admin account if not exists
  const admin = await get("SELECT id FROM users WHERE username = 'admin'");
  if (!admin) {
    const hash = bcrypt.hashSync("admin123", 10);
    await run("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)", ["admin", hash]);
    console.log("✅ Admin account created.");
  }

  console.log("✅ Turso database ready.");
  return { run, all, get };
})();

module.exports = { ready };
