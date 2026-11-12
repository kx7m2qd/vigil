const express = require('express');
const _ = require('lodash');
const app = express();
app.use(express.json());

const settings = {};

app.post('/settings', (req, res) => {
  const { section, key, value } = req.body;
  // ruleid: js-prototype-pollution
  settings[section][key] = value;
  res.end();
});

app.post('/prefs', (req, res) => {
  // ruleid: js-prototype-pollution
  _.set(settings, req.body.path, req.body.value);
  res.end();
});

app.get('/config', function (req, res) {
  const parts = req.query.k.split('.');
  // ruleid: js-prototype-pollution
  config[parts[0]][parts[1]] = req.query.v;
  res.end();
});

app.post('/prefs-fixed', (req, res) => {
  // ok: js-prototype-pollution
  _.set(settings, ['prefs', 'theme'], req.body.value);
  res.end();
});

app.post('/single', (req, res) => {
  // ok: js-prototype-pollution
  settings.user[DEFAULT_KEY] = req.body.value;
  res.end();
});

const store = new Map();
app.post('/kv', (req, res) => {
  // ok: js-prototype-pollution
  store.set(req.body.key, req.body.value);
  res.end();
});

app.post('/bulk', (req, res) => {
  for (const [path, value] of Object.entries(req.body)) {
    const [group, key] = path.split('.');
    // ruleid: js-prototype-pollution
    settings[group][key] = value;
  }
  res.end();
});

app.post('/bulk-safe', (req, res) => {
  for (const [key, value] of Object.entries(req.body)) {
    // ok: js-prototype-pollution
    store.set(key, value);
  }
  res.end();
});
