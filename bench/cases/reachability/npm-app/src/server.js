const express = require("express");
const { Sequelize } = require("sequelize");

// The connection string picks the driver; sequelize loads it itself.
const db = new Sequelize(process.env.DATABASE_URL);
const app = express();
app.use(express.json());

app.get("/orders/:id", async (req, res) => {
  const [rows] = await db.query("SELECT * FROM orders WHERE id = ?", { replacements: [req.params.id] });
  res.json(rows[0] ?? null);
});

app.listen(3000);
