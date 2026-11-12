const cp = require('child_process');
const { exec, execFile, spawn } = require('child_process');
const express = require('express');
const app = express();

app.get('/ping', (req, res) => {
  // ruleid: js-command-injection
  cp.exec('ping -c 1 ' + req.query.host, (err, out) => res.send(out));
});

app.post('/convert', async (req, res) => {
  const name = req.body.filename;
  const cmd = `convert ${name} out.png`;
  // ruleid: js-command-injection
  exec(cmd, () => res.end());
});

app.get('/log', function handler(req, res) {
  // ruleid: js-command-injection
  const out = cp.execSync(`tail -n 50 ${req.params.file}`);
  res.send(out);
});

app.get('/safe-args', (req, res) => {
  // ok: js-command-injection
  execFile('ping', ['-c', '1', req.query.host], (err, out) => res.send(out));
});

app.get('/safe-int', (req, res) => {
  const n = parseInt(req.query.n, 10);
  // ok: js-command-injection
  cp.exec('seq ' + n, (err, out) => res.send(out));
});

app.get('/constant', (req, res) => {
  // ok: js-command-injection
  cp.exec('uptime', (err, out) => res.send(out));
});

app.get('/regex', (req, res) => {
  // ok: js-command-injection
  const m = /^[a-z]+$/.exec(req.query.name);
  res.send(Boolean(m));
});

app.post('/api/install-agent', async (req, res) => {
  const { agentName } = req.body;
  // ruleid: js-command-injection
  const child = spawn('npx', ['claude-code-templates@latest', '--agent', agentName, '--yes'], {
    cwd: process.cwd(),
    shell: true,
  });
  child.on('close', () => res.end());
});

app.post('/api/install-agent-safe', async (req, res) => {
  const { agentName } = req.body;
  // ok: js-command-injection
  const child = spawn('npx', ['claude-code-templates@latest', '--agent', agentName, '--yes'], {
    cwd: process.cwd(),
  });
  child.on('close', () => res.end());
});

app.get('/grep', (req, res) => {
  // ruleid: js-command-injection
  cp.execFileSync('grep', ['-r', req.query.q, '.'], { shell: true });
  res.end();
});
