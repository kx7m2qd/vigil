const express = require('express');
const mongoSanitize = require('mongo-sanitize');
const User = require('./models/user');
const app = express();
app.use(express.json());

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  // ruleid: js-nosql-injection
  const user = await User.findOne({ username: username, password: password });
  res.json({ ok: !!user });
});

app.get('/orders', async (req, res) => {
  // ruleid: js-nosql-injection
  const orders = await db.collection('orders').find({ status: req.query.status }).toArray();
  res.json(orders);
});

app.post('/search', async (req, res) => {
  // ruleid: js-nosql-injection
  const docs = await Product.find(req.body.filter);
  res.json(docs);
});

app.post('/reset', async (req, res) => {
  // ruleid: js-nosql-injection
  await User.updateOne({ email: req.body.email }, { $set: { resetToken: makeToken() } });
  res.end();
});

app.get('/products/:id/reviews', async (req, res) => {
  // A string cast does not help here: `$where` runs the string as JavaScript.
  // ruleid: js-nosql-injection
  const reviews = await Review.find({ $where: `this.product == '${req.params.id}'` });
  res.json(reviews);
});

app.get('/orders/:id', async (req, res) => {
  const id = String(req.query.id);
  // ruleid: js-nosql-injection
  const orders = await Order.find({ '$where': 'this.orderId === ' + id });
  res.json(orders);
});

app.get('/reviews-safe', async (req, res) => {
  // ok: js-nosql-injection
  const reviews = await Review.find({ $where: 'this.likes > 10' });
  res.json(reviews);
});

app.post('/update-filter', async (req, res) => {
  // ruleid: js-nosql-injection
  await User.updateMany(req.body.filter, { $set: { flagged: true } });
  res.end();
});

app.post('/hash', (req, res) => {
  const { password } = req.body;
  // ok: js-nosql-injection
  const a = crypto.createHash('sha256').update(password).digest('hex');
  const h = crypto.createHmac('sha256', key);
  // ok: js-nosql-injection
  h.update(password, 'utf8');
  res.json({ a });
});

app.post('/login-safe', async (req, res) => {
  // ok: js-nosql-injection
  const user = await User.findOne({ username: String(req.body.username) });
  res.json({ ok: !!user });
});

app.get('/orders-safe', async (req, res) => {
  const status = mongoSanitize(req.query.status);
  // ok: js-nosql-injection
  const orders = await Order.find({ status: sanitize(status) });
  res.json(orders);
});

app.get('/users/:id', async (req, res) => {
  // ok: js-nosql-injection
  const user = await User.findOne({ _id: req.params.id });
  res.json(user);
});

app.get('/cart', (req, res) => {
  const items = getCart();
  // ok: js-nosql-injection
  const item = items.find((i) => i.sku === req.query.sku);
  res.json(item);
});
