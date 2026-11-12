const express = require('express');
const serialize = require('node-serialize');
const yaml = require('js-yaml');
const cookieParser = require('cookie-parser');
const app = express();
app.use(cookieParser());

app.get('/profile', (req, res) => {
  const raw = Buffer.from(req.cookies.profile, 'base64').toString();
  // ruleid: js-unsafe-deserialization
  const profile = serialize.unserialize(raw);
  res.send(`Hello ${profile.username}`);
});

app.post('/import', (req, res) => {
  // ruleid: js-unsafe-deserialization
  const doc = yaml.load(req.body.config, { schema: yaml.DEFAULT_FULL_SCHEMA });
  res.json(doc);
});

app.post('/restore', function (req, res) {
  // ruleid: js-unsafe-deserialization
  const state = funcster.deepDeserialize(req.body.state);
  res.json(state);
});

app.get('/profile-safe', (req, res) => {
  const raw = Buffer.from(req.cookies.profile, 'base64').toString();
  // ok: js-unsafe-deserialization
  const profile = JSON.parse(raw);
  res.json(profile);
});

app.post('/import-safe', (req, res) => {
  // ok: js-unsafe-deserialization
  const doc = yaml.load(req.body.config);
  res.json(doc);
});

function loadLocal() {
  // ok: js-unsafe-deserialization
  return serialize.unserialize(fs.readFileSync('./state.bin', 'utf8'));
}
