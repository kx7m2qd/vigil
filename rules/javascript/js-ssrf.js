const axios = require('axios');
const express = require('express');
const app = express();

app.get('/preview', async (req, res) => {
  // ruleid: js-ssrf
  const r = await fetch(req.query.url);
  res.send(await r.text());
});

app.post('/webhook-test', async (req, res) => {
  const target = req.body.callbackUrl;
  // ruleid: js-ssrf
  await axios.post(target, { ping: true });
  res.end();
});

app.get('/proxy', async (req, res) => {
  // ruleid: js-ssrf
  const r = await axios.get(`${req.query.host}/status`);
  res.json(r.data);
});

app.get('/user/:id', async (req, res) => {
  // ok: js-ssrf
  const r = await fetch('https://api.example.com/users/' + req.params.id);
  res.json(await r.json());
});

app.get('/repo', async (req, res) => {
  // ok: js-ssrf
  const r = await axios.get(`https://api.github.com/repos/${req.query.repo}`);
  res.json(r.data);
});

app.get('/fixed', async (req, res) => {
  // ok: js-ssrf
  const r = await fetch('https://status.example.com/health');
  res.send(await r.text());
});
