const jwt = require("jsonwebtoken");

function issue(user) {
  // expect: js-jwt-hardcoded-secret
  return jwt.sign({ sub: user.id }, "super-secret-signing-key", { expiresIn: "1h" });
}

function verifyLegacy(token) {
  // expect: js-jwt-insecure-verify
  return jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256", "none"] });
}

function verifyLongLived(token) {
  // expect: js-jwt-insecure-verify
  return jwt.verify(token, process.env.JWT_SECRET, { ignoreExpiration: true });
}

// Safe: secret from env, pinned algorithm.
function verify(token) {
  return jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"] });
}

function issueSafe(user) {
  return jwt.sign({ sub: user.id }, process.env.JWT_SECRET, { expiresIn: "1h" });
}

module.exports = { issue, issueSafe, verify, verifyLegacy, verifyLongLived };
