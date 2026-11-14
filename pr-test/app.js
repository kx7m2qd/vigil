const db = require("./db");

exports.find = (req) => {
  const q = "SELECT * FROM users WHERE id=" + req.query.id;
  return db.query(q);
};
