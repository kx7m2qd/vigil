const crypto = require('crypto');

function createSession(user) {
  // ruleid: js-weak-random
  const sessionId = Math.random().toString(36).slice(2);
  sessions.set(sessionId, user.id);
  return sessionId;
}

function generateResetToken() {
  // ruleid: js-weak-random
  return Math.floor(Math.random() * 1e16).toString(16);
}

async function sendOtp(user) {
  // ruleid: js-weak-random
  user.otpCode = String(Math.floor(100000 + Math.random() * 900000));
  await user.save();
}

app.post('/login', (req, res) => {
  const value = Math.random().toString(36).substring(2);
  // ruleid: js-weak-random
  res.cookie('session', value, { httpOnly: true });
  res.end();
});

function createSessionSafe(user) {
  // ok: js-weak-random
  const sessionId = crypto.randomBytes(32).toString('hex');
  sessions.set(sessionId, user.id);
  return sessionId;
}

function backoff(attempt) {
  // ok: js-weak-random
  const delay = 2 ** attempt * 100 + Math.random() * 100;
  return delay;
}

function pickColor() {
  // ok: js-weak-random
  return COLORS[Math.floor(Math.random() * COLORS.length)];
}
