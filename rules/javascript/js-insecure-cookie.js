const express = require('express');
const session = require('express-session');
const app = express();

app.use(
  // ruleid: js-insecure-cookie
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: false },
  })
);

app.post('/login', (req, res) => {
  const token = issueToken(req.user);
  // ruleid: js-insecure-cookie
  res.cookie('auth_token', token, { httpOnly: true });
  res.end();
});

app.post('/remember', (req, res) => {
  // ruleid: js-insecure-cookie
  res.cookie('remember_me', makeId(), { maxAge: 30 * 86400e3, secure: false });
  res.end();
});

app.post('/login-safe', (req, res) => {
  // ok: js-insecure-cookie
  res.cookie('auth_token', issueToken(req.user), { httpOnly: true, secure: true, sameSite: 'lax' });
  res.end();
});

app.get('/theme', (req, res) => {
  // ok: js-insecure-cookie
  res.cookie('theme', 'dark');
  res.end();
});

app.use(
  // ok: js-insecure-cookie
  session({ secret: process.env.SESSION_SECRET, cookie: { secure: true, httpOnly: true } })
);
