const jwt = require('jsonwebtoken');

function issue(user) {
  // ruleid: js-jwt-hardcoded-secret
  return jwt.sign({ sub: user.id }, 'super-secret-key-123', { expiresIn: '1h' });
}

const SECRET = 'changeme';
function check(token) {
  // ruleid: js-jwt-hardcoded-secret
  return jwt.verify(token, SECRET);
}

function issueSafe(user) {
  // ok: js-jwt-hardcoded-secret
  return jwt.sign({ sub: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
}

function checkSafe(token, publicKey) {
  // ok: js-jwt-hardcoded-secret
  return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
}
