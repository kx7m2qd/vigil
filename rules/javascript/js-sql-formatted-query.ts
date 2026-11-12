import { Pool } from 'pg';
import mysql from 'mysql2';

class PgDataStore {
  constructor(private pgPool: Pool) {}

  async getRoomsVisibility(roomIds: string[]) {
    const list = `('${roomIds.join("','")}')`;
    // ruleid: js-sql-formatted-query
    const res = await this.pgPool.query(`SELECT room_id, visibility FROM room_visibility WHERE room_id IN ${list}`);
    return res.rows;
  }

  async userByEmail(email: string) {
    // ruleid: js-sql-formatted-query
    return this.pgPool.query("SELECT * FROM users WHERE email = '" + email + "'");
  }

  async deleteOlderThan(table: string, days: number) {
    const sql = `DELETE FROM ${table} WHERE created_at < now() - interval '${days} days'`;
    // ruleid: js-sql-formatted-query
    return this.pgPool.query(sql);
  }

  async getRoomsVisibilitySafe(roomIds: string[]) {
    // ok: js-sql-formatted-query
    const res = await this.pgPool.query('SELECT room_id, visibility FROM room_visibility WHERE room_id = ANY($1)', [roomIds]);
    return res.rows;
  }

  async userByEmailSafe(email: string) {
    // ok: js-sql-formatted-query
    return this.pgPool.query('SELECT * FROM users WHERE email = $1', [email]);
  }

  async userById(id: string) {
    // ok: js-sql-formatted-query
    return this.pgPool.query(`SELECT * FROM users WHERE id = ${Number(id)}`);
  }
}

function search(router: { query: (s: string) => void }, term: string) {
  // ok: js-sql-formatted-query
  router.query(`/search?q=${term}`);
}

function orders(db: { query: (s: string) => void }, userId: string, sort: string, status: string) {
  const id = Number(userId);
  // ok: js-sql-formatted-query
  db.query('SELECT * FROM orders WHERE user_id = ' + id);
  // ok: js-sql-formatted-query
  db.query('SELECT id FROM orders ORDER BY ' + mysql.escapeId(sort));
  // ruleid: js-sql-formatted-query
  db.query('SELECT * FROM orders WHERE user_id = ' + id + " AND status = '" + status + "'");
}
