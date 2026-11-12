const express = require("express");
const mysql = require("mysql2");
const db = mysql.createPool({ host: process.env.DB_HOST, user: "app", database: "app" });

const router = express.Router();

router.get("/users/:id", (req, res) => {
  const sql = "SELECT id, name, email FROM users WHERE id = " + req.params.id;
  // expect: js-sql-injection
  db.query(sql, (err, rows) => res.json(rows));
});

router.get("/users", (req, res) => {
  const { sort } = req.query;
  // expect: js-sql-injection
  db.query(`SELECT id, name FROM users ORDER BY ${sort}`, (err, rows) => res.json(rows));
});

// Safe: parameterized.
router.get("/users/by-email", (req, res) => {
  db.query("SELECT id, name FROM users WHERE email = ?", [req.query.email], (err, rows) => res.json(rows));
});

// Safe: numeric coercion.
router.get("/users/:id/orders", (req, res) => {
  const id = Number(req.params.id);
  db.query("SELECT * FROM orders WHERE user_id = " + id, (err, rows) => res.json(rows));
});

// Safe: allow-listed sort column.
const SORTABLE = new Set(["name", "created_at"]);
router.get("/admin/users", (req, res) => {
  const sort = SORTABLE.has(req.query.sort) ? req.query.sort : "name";
  db.query("SELECT id, name FROM users ORDER BY " + mysql.escapeId(sort), (err, rows) => res.json(rows));
});

module.exports = router;
