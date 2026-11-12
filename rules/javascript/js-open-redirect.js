const express = require('express');
const app = express();

app.get('/login', (req, res) => {
  // ... authenticate ...
  // ruleid: js-open-redirect
  res.redirect(req.query.next);
});

app.post('/logout', function (req, res) {
  const returnTo = req.body.returnTo || '/';
  // ruleid: js-open-redirect
  res.redirect(302, returnTo);
});

app.get('/out', (req, res) => {
  // ruleid: js-open-redirect
  res.writeHead(302, { Location: req.query.url });
  res.end();
});

app.get('/go', (req, res) => {
  // ruleid: js-open-redirect
  res.redirect(`${req.query.host}/welcome`);
});

app.get('/user/:id', (req, res) => {
  // ok: js-open-redirect
  res.redirect('/profile/' + req.params.id);
});

app.get('/docs', (req, res) => {
  // ok: js-open-redirect
  res.redirect(`https://docs.example.com/${encodeURIComponent(req.query.page)}`);
});

const TARGETS = { home: '/', billing: '/settings/billing' };
app.get('/jump', (req, res) => {
  // ok: js-open-redirect
  res.redirect(TARGETS.home);
});

app.get('/after-login', (req, res) => {
  // ok: js-open-redirect
  res.redirect('/dashboard');
});
