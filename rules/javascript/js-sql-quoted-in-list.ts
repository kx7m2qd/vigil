function cte(tableName: string, nodeIds: string[]) {
  return `WITH RECURSIVE cte AS (
      SELECT id, parent_id FROM ${tableName}
      // ruleid: js-sql-quoted-in-list
      WHERE id IN ('${nodeIds.join("','")}')
    ) SELECT * FROM cte`;
}

function rooms(roomIds: string[]) {
  // ruleid: js-sql-quoted-in-list
  return `('${roomIds.join("','")}')`;
}

function legacy(ids: string[]) {
  // ruleid: js-sql-quoted-in-list
  return "SELECT * FROM t WHERE id IN ('" + ids.join("', '") + "')";
}

function safe(ids: string[]) {
  // ok: js-sql-quoted-in-list
  return { text: 'SELECT * FROM t WHERE id = ANY($1)', values: [ids] };
}

function placeholders(ids: string[]) {
  // ok: js-sql-quoted-in-list
  return `SELECT * FROM t WHERE id IN (${ids.map((_, i) => `$${i + 1}`).join(', ')})`;
}

function csv(names: string[]) {
  // ok: js-sql-quoted-in-list
  return names.join(', ');
}
