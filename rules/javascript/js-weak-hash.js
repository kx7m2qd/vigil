const crypto = require('crypto');
const md5 = require('md5');
const bcrypt = require('bcrypt');

async function register(req, res) {
  const { email, password } = req.body;
  // ruleid: js-weak-hash
  const hash = crypto.createHash('md5').update(password).digest('hex');
  await db.users.insert({ email, passwordHash: hash });
}

function checkLogin(user, input) {
  const h = crypto.createHash('sha1');
  // ruleid: js-weak-hash
  h.update(input.password);
  return h.digest('hex') === user.passwordHash;
}

function storeApiSecret(cfg) {
  // ruleid: js-weak-hash
  return md5(cfg.clientSecret);
}

async function registerSafe(req, res) {
  const { email, password } = req.body;
  // ok: js-weak-hash
  const hash = await bcrypt.hash(password, 12);
  await db.users.insert({ email, passwordHash: hash });
}

function etag(body) {
  // ok: js-weak-hash
  return crypto.createHash('md5').update(body).digest('hex');
}

function sign(password) {
  // ok: js-weak-hash
  return crypto.createHash('sha256').update(password).digest('hex');
}
