const express = require('express');
const libxmljs = require('libxmljs');
const { XMLParser } = require('fast-xml-parser');
const app = express();
app.use(express.text({ type: 'application/xml' }));

app.post('/invoice', (req, res) => {
  // ruleid: js-xxe
  const doc = libxmljs.parseXml(req.body, { noent: true, noblanks: true });
  res.json({ total: doc.get('//total').text() });
});

app.post('/feed', async (req, res) => {
  // ruleid: js-xxe
  const doc = await libxml.parseXmlAsync(req.body, { noent: true });
  res.send(doc.toString());
});

function parseUpload(buf) {
  // ruleid: js-xxe
  return libxmljs.parseXmlString(buf.toString(), { dtdload: true, noent: true });
}

app.post('/invoice-safe', (req, res) => {
  // ok: js-xxe
  const doc = libxmljs.parseXml(req.body, { nonet: true });
  res.json({ total: doc.get('//total').text() });
});

app.post('/invoice-plain', (req, res) => {
  // ok: js-xxe
  const doc = libxmljs.parseXml(req.body);
  res.json({ total: doc.get('//total').text() });
});

app.post('/invoice-fxp', (req, res) => {
  // ok: js-xxe
  const doc = new XMLParser().parse(req.body);
  res.json(doc);
});
