const Database = require("better-sqlite3");

const db = new Database("forum.db");

db.pragma("journal_mode = WAL");

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        telegram_id TEXT UNIQUE NOT NULL,

        username TEXT,
        first_name TEXT,
        last_name TEXT,
        photo_url TEXT,

        role TEXT NOT NULL DEFAULT 'member',

        warnings INTEGER NOT NULL DEFAULT 0,

        banned INTEGER NOT NULL DEFAULT 0,

        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
`);

console.log("База данных подключена.");

module.exports = db;