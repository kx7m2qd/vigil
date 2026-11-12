const vm = require('vm');
const express = require('express');
const app = express();

app.post('/calc', (req, res) => {
  // ruleid: js-code-injection
  res.json({ result: eval(req.body.expression) });
});

app.post('/rule', (req, res) => {
  // ruleid: js-code-injection
  const fn = new Function('order', 'return ' + req.body.condition);
  res.json({ ok: fn({ total: 10 }) });
});

app.post('/sandbox', (req, res) => {
  const code = req.body.script;
  // ruleid: js-code-injection
  res.json(vm.runInNewContext(code, {}));
});

app.post('/safe-json', (req, res) => {
  const data = JSON.parse(req.body.payload);
  // ok: js-code-injection
  res.json(eval('1 + 1') + data.n);
});

app.get('/safe-timeout', (req, res) => {
  // ok: js-code-injection
  setTimeout(() => res.send('done'), Number(req.query.delay));
});
