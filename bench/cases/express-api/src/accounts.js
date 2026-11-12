const express = require("express");
const crypto = require("crypto");
const session = require("express-session");
const User = require("../models/user");

const router = express.Router();

router.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    // expect: js-insecure-cookie
    cookie: { httpOnly: true, secure: false, maxAge: 86400e3 },
  })
);

router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  // expect: js-nosql-injection
  const user = await User.findOne({ email, active: true });
  if (!user) return res.status(401).end();
  // expect: js-weak-hash
  const digest = crypto.createHash("md5").update(password).digest("hex");
  if (digest !== user.passwordHash) return res.status(401).end();
  req.session.userId = user.id;
  const next = req.query.next || "/";
  // expect: js-open-redirect
  res.redirect(next);
});

router.post("/forgot", async (req, res) => {
  const user = await User.findOne({ email: String(req.body.email) });
  if (user) {
    // expect: js-weak-random
    user.resetToken = Math.random().toString(36).slice(2) + Date.now().toString(36);
    await user.save();
    await mailer.sendReset(user.email, user.resetToken);
  }
  res.status(202).end();
});

// Safe: crypto RNG, typed lookup, relative-only redirect, secure cookie.
router.post("/forgot-v2", async (req, res) => {
  const user = await User.findOne({ email: String(req.body.email) });
  if (user) {
    user.resetToken = crypto.randomBytes(32).toString("hex");
    await user.save();
  }
  res.status(202).end();
});

router.post("/remember", (req, res) => {
  res.cookie("remember_me", crypto.randomUUID(), { httpOnly: true, secure: true, sameSite: "lax" });
  res.redirect("/dashboard");
});

router.get("/avatar/:id", async (req, res) => {
  const user = await User.findOne({ _id: req.params.id });
  res.redirect(`https://cdn.example.com/avatars/${user.avatar}`);
});

module.exports = router;
