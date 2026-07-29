'use strict';

const session = require('express-session');

class SqliteSessionStore extends session.Store {
  constructor(db) {
    super();
    this.db = db;
  }

  get(sid, callback) {
    try {
      const row = this.db.prepare('SELECT sess, expires_at FROM sessions_store WHERE sid = ?').get(sid);
      if (!row) return callback(null, null);
      if (row.expires_at <= Date.now()) {
        this.db.prepare('DELETE FROM sessions_store WHERE sid = ?').run(sid);
        return callback(null, null);
      }
      return callback(null, JSON.parse(row.sess));
    } catch (error) {
      return callback(error);
    }
  }

  set(sid, value, callback) {
    try {
      const expiresAt = value?.cookie?.expires
        ? new Date(value.cookie.expires).getTime()
        : Date.now() + (7 * 24 * 60 * 60 * 1000);
      this.db.prepare(`
        INSERT INTO sessions_store (sid, sess, expires_at, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(sid) DO UPDATE SET
          sess = excluded.sess,
          expires_at = excluded.expires_at,
          updated_at = excluded.updated_at
      `).run(sid, JSON.stringify(value), expiresAt, Date.now());
      if (callback) callback(null);
    } catch (error) {
      if (callback) callback(error);
    }
  }

  destroy(sid, callback) {
    try {
      this.db.prepare('DELETE FROM sessions_store WHERE sid = ?').run(sid);
      if (callback) callback(null);
    } catch (error) {
      if (callback) callback(error);
    }
  }

  touch(sid, value, callback) {
    try {
      const expiresAt = value?.cookie?.expires
        ? new Date(value.cookie.expires).getTime()
        : Date.now() + (7 * 24 * 60 * 60 * 1000);
      this.db.prepare('UPDATE sessions_store SET expires_at = ?, updated_at = ? WHERE sid = ?')
        .run(expiresAt, Date.now(), sid);
      if (callback) callback(null);
    } catch (error) {
      if (callback) callback(error);
    }
  }
}

module.exports = SqliteSessionStore;
