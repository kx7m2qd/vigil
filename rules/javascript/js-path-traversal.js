const fs = require('fs');
const path = require('path');
const express = require('express');
const app = express();

app.get('/files', (req, res) => {
  // ruleid: js-path-traversal
  fs.readFile('/srv/uploads/' + req.query.name, (err, data) => res.send(data));
});

app.get('/avatar/:file', (req, res) => {
  const p = path.join(__dirname, 'avatars', req.params.file);
  // ruleid: js-path-traversal
  res.sendFile(p);
});

app.post('/save', async (req, res) => {
  // ruleid: js-path-traversal
  await fs.promises.writeFile(`./data/${req.body.name}.json`, JSON.stringify(req.body.content));
  res.end();
});

app.get('/safe-basename', (req, res) => {
  const name = path.basename(req.query.name);
  // ok: js-path-traversal
  fs.readFile(path.join('/srv/uploads', name), (err, data) => res.send(data));
});

app.get('/safe-root/:file', (req, res) => {
  // ok: js-path-traversal
  res.sendFile(req.params.file, { root: path.join(__dirname, 'public') });
});

app.get('/static', (req, res) => {
  // ok: js-path-traversal
  fs.readFile('./config/defaults.json', (err, data) => res.send(data));
});
