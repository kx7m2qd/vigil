const express = require("express");
const escapeHtml = require("escape-html");
const serialize = require("node-serialize");
const libxmljs = require("libxmljs");
const _ = require("lodash");

const router = express.Router();
const prefs = {};

router.get("/search", (req, res) => {
  const q = req.query.q || "";
  const hits = index.search(q);
  // expect: js-xss
  res.send(`<h2>${hits.length} results for "${q}"</h2>` + hits.map(renderHit).join(""));
});

router.get("/search/v2", (req, res) => {
  const q = req.query.q || "";
  res.send(`<h2>Results for "${escapeHtml(q)}"</h2>`);
});

router.get("/grep", (req, res) => {
  // expect: js-redos
  const re = new RegExp(req.query.pattern, "i");
  res.json(logLines.filter((l) => re.test(l)));
});

router.get("/grep/v2", (req, res) => {
  const needle = String(req.query.pattern).toLowerCase();
  res.json(logLines.filter((l) => l.toLowerCase().includes(needle)));
});

router.post("/prefs", (req, res) => {
  for (const [path, value] of Object.entries(req.body)) {
    const [group, key] = path.split(".");
    prefs[group] = prefs[group] || {};
    // expect: js-prototype-pollution
    prefs[group][key] = value;
  }
  res.json(prefs);
});

router.post("/prefs/v2", (req, res) => {
  const store = new Map(Object.entries(req.body));
  res.json(Object.fromEntries(store));
});

router.get("/cart", (req, res) => {
  if (!req.cookies.cart) return res.json([]);
  // expect: js-unsafe-deserialization
  const cart = serialize.unserialize(Buffer.from(req.cookies.cart, "base64").toString());
  res.json(cart.items);
});

router.get("/cart/v2", (req, res) => {
  const cart = req.cookies.cart ? JSON.parse(Buffer.from(req.cookies.cart, "base64").toString()) : {};
  res.json(cart.items || []);
});

router.post("/import", express.text({ type: "application/xml" }), (req, res) => {
  // expect: js-xxe
  const doc = libxmljs.parseXml(req.body, { noent: true, noblanks: true });
  res.json({ rows: doc.find("//row").length });
});

router.post("/import/v2", express.text({ type: "application/xml" }), (req, res) => {
  const doc = libxmljs.parseXml(req.body, { nonet: true });
  res.json({ rows: doc.find("//row").length });
});

module.exports = router;
