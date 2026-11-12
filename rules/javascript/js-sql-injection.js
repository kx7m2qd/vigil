const express = require('express');
const { pool } = require('./db');
const { prisma } = require('./prisma');
const app = express();

app.get('/users', async (req, res) => {
  // ruleid: js-sql-injection
  const rows = await pool.query("SELECT * FROM users WHERE name = '" + req.query.name + "'");
  res.json(rows);
});

app.get('/orders/:id', async (req, res) => {
  const sql = `SELECT * FROM orders WHERE id = ${req.params.id}`;
  // ruleid: js-sql-injection
  res.json(await pool.query(sql));
});

app.post('/search', async (req, res) => {
  const { term } = req.body;
  // ruleid: js-sql-injection
  res.json(await prisma.$queryRawUnsafe(`SELECT * FROM posts WHERE title LIKE '%${term}%'`));
});

app.get('/safe', async (req, res) => {
  // ok: js-sql-injection
  const rows = await pool.query('SELECT * FROM users WHERE name = $1', [req.query.name]);
  res.json(rows);
});

app.get('/safe-int/:id', async (req, res) => {
  const id = Number(req.params.id);
  // ok: js-sql-injection
  res.json(await pool.query(`SELECT * FROM orders WHERE id = ${id}`));
});

app.get('/safe-prisma', async (req, res) => {
  // ok: js-sql-injection
  res.json(await prisma.$queryRaw`SELECT * FROM posts WHERE id = ${req.query.id}`);
});
