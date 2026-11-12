const express = require('express');
const escapeHtml = require('escape-html');
const DOMPurify = require('dompurify');
const app = express();

app.get('/search', (req, res) => {
  // ruleid: js-xss
  res.send(`<h1>Results for ${req.query.q}</h1>`);
});

app.get('/hello', function (req, res) {
  const name = req.query.name;
  // ruleid: js-xss
  res.status(200).send('<p>Hello ' + name + '</p>');
});

app.post('/comment', (req, res) => {
  const { body } = req.body;
  // ruleid: js-xss
  res.write('<div class="comment">' + body + '</div>');
  res.end();
});

function showTab() {
  const tab = decodeURIComponent(location.hash.slice(1));
  // ruleid: js-xss
  document.getElementById('title').innerHTML = 'Tab: ' + tab;
}

function showNext() {
  const next = new URLSearchParams(window.location.search).get('msg');
  // ruleid: js-xss
  document.body.insertAdjacentHTML('beforeend', next);
}

app.get('/search-safe', (req, res) => {
  // ok: js-xss
  res.send(`<h1>Results for ${escapeHtml(req.query.q)}</h1>`);
});

app.get('/api/user', (req, res) => {
  // ok: js-xss
  res.json({ name: req.query.name });
});

app.get('/page/:n', (req, res) => {
  const n = parseInt(req.params.n, 10);
  // ok: js-xss
  res.send('<p>Page ' + n + '</p>');
});

function showTabSafe() {
  const tab = decodeURIComponent(location.hash.slice(1));
  // ok: js-xss
  document.getElementById('title').textContent = 'Tab: ' + tab;
}

function renderBio(html) {
  const bio = new URLSearchParams(location.search).get('bio');
  // ok: js-xss
  document.getElementById('bio').innerHTML = DOMPurify.sanitize(bio);
}

app.get('/raw', async (req, res) => {
  const data = await fs.promises.readFile('/srv/uploads/' + req.query.name, 'utf8');
  // ok: js-xss
  res.send(data);
});

app.get('/proxy', async (req, res) => {
  const page = await axios.get(req.query.url);
  // ruleid: js-xss
  res.send(page.data);
});
