const express = require("express");
const fs = require("fs");
const path = require("path");
const { exec, execFile } = require("child_process");
const axios = require("axios");

const UPLOADS = path.join(__dirname, "..", "uploads");
const app = express();

app.get("/download", (req, res) => {
  const file = path.join(UPLOADS, req.query.name);
  // expect: js-path-traversal
  res.sendFile(file);
});

app.get("/raw", async (req, res) => {
  // expect: js-path-traversal
  const data = await fs.promises.readFile(UPLOADS + "/" + req.query.name, "utf8");
  res.send(data);
});

// Safe: basename strips directories.
app.get("/download-safe", (req, res) => {
  res.sendFile(path.join(UPLOADS, path.basename(req.query.name)));
});

app.post("/thumbnail", (req, res) => {
  // expect: js-command-injection
  exec(`convert ${req.body.file} -resize 128x128 thumb.png`, (err) => res.sendStatus(err ? 500 : 200));
});

// Safe: argument vector, no shell.
app.post("/thumbnail-safe", (req, res) => {
  execFile("convert", [path.basename(req.body.file), "-resize", "128x128", "thumb.png"], (err) =>
    res.sendStatus(err ? 500 : 200),
  );
});

app.get("/preview", async (req, res) => {
  // expect: js-ssrf
  const page = await axios.get(req.query.url);
  // expect: js-xss
  res.send(page.data);
});

// Safe: fixed host, user input only in the query string.
app.get("/weather", async (req, res) => {
  const r = await axios.get("https://api.weather.example/v1/now", { params: { city: req.query.city } });
  res.json(r.data);
});

app.post("/calc", (req, res) => {
  // expect: js-code-injection
  res.json({ result: eval(req.body.expression) });
});

// Safe: JSON.parse is not code execution.
app.post("/settings", (req, res) => {
  res.json(JSON.parse(req.body.settings));
});

module.exports = app;
