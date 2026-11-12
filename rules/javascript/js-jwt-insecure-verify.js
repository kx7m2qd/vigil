const jwt = require('jsonwebtoken');

function authA(token, key) {
  // ruleid: js-jwt-insecure-verify
  return jwt.verify(token, key, { algorithms: ['HS256', 'none'] });
}

function authB(token, key) {
  // ruleid: js-jwt-insecure-verify
  return jwt.verify(token, key, { algorithms: ['RS256'], ignoreExpiration: true });
}

function safeA(token, key) {
  // ok: js-jwt-insecure-verify
  return jwt.verify(token, key, { algorithms: ['RS256'] });
}

function safeB(token, key) {
  // ok: js-jwt-insecure-verify
  return jwt.verify(token, key, { algorithms: ['RS256'], ignoreExpiration: false });
}
