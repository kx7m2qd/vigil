// Harder, realistic shapes: input passes through a helper or a named handler.
const { exec } = require("child_process");
const db = require("./db");

function findByStatus(status) {
  // expect: js-sql-injection
  return db.query("SELECT * FROM reports WHERE status = '" + status + "'");
}

async function listReports(req, res) {
  res.json(await findByStatus(req.query.status));
}

async function archive(req, res) {
  const { name } = req.body;
  const cmd = "tar czf /archives/" + name + ".tgz /reports/" + name;
  // expect: js-command-injection
  exec(cmd, () => res.sendStatus(202));
}

module.exports = { listReports, archive };
