const express = require('express');
const _ = require('lodash');
const app = express();

app.get('/search', (req, res) => {
  // ruleid: js-redos
  const re = new RegExp(req.query.q, 'i');
  res.json(products.filter((p) => re.test(p.name)));
});

app.post('/filter', function (req, res) {
  const { pattern } = req.body;
  // ruleid: js-redos
  const matcher = RegExp('^' + pattern + '$');
  res.json(logs.filter((l) => matcher.test(l)));
});

app.get('/highlight', (req, res) => {
  // ruleid: js-redos
  const re = new RegExp(`\\b${req.query.word}\\b`, 'g');
  res.send(text.replace(re, '<mark>$&</mark>'));
});

app.get('/search-safe', (req, res) => {
  // ok: js-redos
  const re = new RegExp(_.escapeRegExp(req.query.q), 'i');
  res.json(products.filter((p) => re.test(p.name)));
});

app.get('/search-escaped', (req, res) => {
  const q = req.query.q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // ok: js-redos
  const re = new RegExp(q, 'i');
  res.json(products.filter((p) => re.test(p.name)));
});

app.get('/contains', (req, res) => {
  // ok: js-redos
  res.json(products.filter((p) => p.name.includes(req.query.q)));
});
