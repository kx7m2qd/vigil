import sqlite3

import pandas as pd
from sqlalchemy import text


def delete_key(curs, issuer, key_id):
    # ruleid: py-sql-formatted-query
    curs.execute("DELETE FROM keycache WHERE issuer = '{}' AND key_id = '{}'".format(issuer, key_id))


def find_links(c, data):
    statuses = "','".join(x[3] for x in data)
    # ruleid: py-sql-formatted-query
    c.execute(f"SELECT id FROM links WHERE url IN ('{statuses}')")


def tasks(db, workflow_id):
    query = """SELECT task_id FROM task
               WHERE task.run_id='%s'""" % (workflow_id)
    # ruleid: py-sql-formatted-query
    return pd.read_sql_query(query, db.engine)


def srid(connection, schema_name, name):
    # ruleid: py-sql-formatted-query
    return connection.execute(text(f"SELECT Find_SRID('{schema_name}', '{name}');")).fetchone()


async def spend(prisma_client, api_key):
    sql_query = (
        """SELECT * FROM "LiteLLM_SpendLogs" WHERE api_key = '"""
        + api_key
        + """' ORDER BY "date";"""
    )
    # ruleid: py-sql-formatted-query
    return await prisma_client.db.query_raw(query=sql_query)


def by_name(cur, name):
    sql = "SELECT * FROM users WHERE name = '" + name + "'"
    # ruleid: py-sql-formatted-query
    cur.execute(sql)


def delete_key_safe(curs, issuer, key_id):
    # ok: py-sql-formatted-query
    curs.execute("DELETE FROM keycache WHERE issuer = ? AND key_id = ?", [issuer, key_id])


def tasks_safe(db, workflow_id):
    query = "SELECT task_id FROM task WHERE task.run_id = %(run_id)s"
    # ok: py-sql-formatted-query
    return pd.read_sql_query(query, db.engine, params={"run_id": workflow_id})


def srid_safe(connection, schema_name, name):
    # ok: py-sql-formatted-query
    return connection.execute(text("SELECT Find_SRID(:schema, :name);"), {"schema": schema_name, "name": name})


def count_users(cur):
    # ok: py-sql-formatted-query
    cur.execute("SELECT count(*) FROM users WHERE active = 1")


def log_line(logger, n):
    # ok: py-sql-formatted-query
    logger.execute(f"processed {n} rows")


def find_links_safe(c, data):
    urls = [x[3] for x in data]
    placeholders = ",".join("?" * len(urls))
    # ok: py-sql-formatted-query
    c.execute(f"SELECT id FROM links WHERE url IN ({placeholders})", urls)


def find_links_inline_safe(c, urls):
    # ok: py-sql-formatted-query
    c.execute(f"SELECT id FROM links WHERE url IN ({', '.join(['%s'] * len(urls))})", urls)


def find_links_table(c, table, urls):
    placeholders = ",".join("?" for _ in urls)
    # ruleid: py-sql-formatted-query
    c.execute(f"SELECT id FROM {table} WHERE url IN ({placeholders})", urls)


def by_password(cur, password):
    sql = f"SELECT username FROM users WHERE password = ?"
    # ok: py-sql-formatted-query
    cur.execute(sql, (password,))
