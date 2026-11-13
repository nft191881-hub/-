'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const express = require('express');

// Load a local .env file without an extra dependency. Existing process variables win.
async function loadEnvFile() {
  try {
    const text = await fs.readFile(path.join(__dirname, '.env'), 'utf8');
    for (const line of text.split(/\r?\n/)) {
      const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
      if (!match || Object.hasOwn(process.env, match[1])) continue;
      let value = match[2];
      if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
      process.env[match[1]] = value;
    }
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}

const DATA_FILE = path.join(__dirname, 'data', 'store.json');
const COOKIE_NAME = 'orange_admin';
const app = express();
const PORT = Number(process.env.PORT) || 3000;
let sessionSecret;
let writeQueue = Promise.resolve();

app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));

function defaultStore() {
  return { products: [], orders: [] };
}

async function readStore() {
  try {
    const parsed = JSON.parse(await fs.readFile(DATA_FILE, 'utf8'));
    if (!Array.isArray(parsed.products) || !Array.isArray(parsed.orders)) throw new Error('store.json must contain products and orders arrays');
    return parsed;
  } catch (error) {
    if (error.code === 'ENOENT') return defaultStore();
    throw error;
  }
}

// Serialize modifications and use an atomic rename so concurrent requests do not overwrite each other.
function updateStore(mutator) {
  const task = writeQueue.then(async () => {
    const store = await readStore();
    const result = await mutator(store);
    const tempFile = `${DATA_FILE}.${process.pid}.tmp`;
    await fs.writeFile(tempFile, `${JSON.stringify(store, null, 2)}\n`, 'utf8');
    await fs.rename(tempFile, DATA_FILE);
    return result;
  });
  writeQueue = task.catch(() => {});
  return task;
}

function safeEqual(a, b) {
  const left = crypto.createHash('sha256').update(String(a)).digest();
  const right = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(left, right);
}

function signSession(expiry) {
  return crypto.createHmac('sha256', sessionSecret).update(String(expiry)).digest('base64url');
}

function cookieValue(req) {
  const header = req.headers.cookie || '';
  const entry = header.split(';').map(part => part.trim()).find(part => part.startsWith(`${COOKIE_NAME}=`));
  return entry ? decodeURIComponent(entry.slice(COOKIE_NAME.length + 1)) : '';
}

function isAdmin(req) {
  const [expiry, signature, extra] = cookieValue(req).split('.');
  if (!expiry || !signature || extra || !/^\d+$/.test(expiry) || Number(expiry) < Date.now()) return false;
  return safeEqual(signature, signSession(expiry));
}

function requireAdmin(req, res, next) {
  if (!isAdmin(req)) return res.status(401).json({ error: '请先登录后台' });
  next();
}

function requireSameOrigin(req, res, next) {
  const origin = req.get('origin');
  if (origin && new URL(origin).host !== req.get('host')) return res.status(403).json({ error: '请求来源校验失败' });
  next();
}

function cleanText(value, maxLength) {
  return typeof value === 'string' ? value.trim().slice(0, maxLength) : '';
}

app.get('/api/health', (req, res) => res.json({ ok: true, payment: 'not_configured' }));

app.get('/api/products', async (req, res, next) => {
  try {
    const store = await readStore();
    res.json(store.products.map(({ id, title, price, sales, img, stock, tag, category }) => ({ id, title, price, sales, img, stock, tag, category })));
  } catch (error) { next(error); }
});

// This creates an unpaid order and reserves the requested stock. It does NOT charge a customer.
app.post('/api/orders', async (req, res, next) => {
  try {
    const name = cleanText(req.body?.customer?.name, 80);
    const phone = cleanText(req.body?.customer?.phone, 30);
    const address = cleanText(req.body?.customer?.address, 300);
    const items = req.body?.items;
    if (!name || !/^1\d{10}$/.test(phone) || !address || !Array.isArray(items) || items.length < 1 || items.length > 20) {
      return res.status(400).json({ error: '请填写有效的收货人、手机号、地址和商品' });
    }

    const normalized = new Map();
    for (const item of items) {
      const id = Number(item?.productId);
      const quantity = Number(item?.quantity);
      if (!Number.isSafeInteger(id) || !Number.isSafeInteger(quantity) || quantity < 1 || quantity > 99) {
        return res.status(400).json({ error: '商品或数量格式无效' });
      }
      normalized.set(id, (normalized.get(id) || 0) + quantity);
    }

    const order = await updateStore(store => {
      const lines = [];
      let total = 0;
      for (const [id, quantity] of normalized) {
        const product = store.products.find(entry => Number(entry.id) === id);
        if (!product) throw Object.assign(new Error('商品不存在'), { status: 404 });
        if (!Number.isSafeInteger(Number(product.stock)) || Number(product.stock) < quantity) {
          throw Object.assign(new Error(`库存不足：${product.title}`), { status: 409 });
        }
        const price = Number(product.price);
        if (!Number.isFinite(price) || price < 0) throw Object.assign(new Error('商品价格配置无效'), { status: 500 });
        lines.push({ productId: id, title: product.title, price, quantity });
        total += price * quantity;
      }
      for (const line of lines) {
        const product = store.products.find(entry => Number(entry.id) === line.productId);
        product.stock = Number(product.stock) - line.quantity;
      }
      const created = {
        id: crypto.randomUUID(),
        items: lines,
        customer: { name, phone, address },
        total: Number(total.toFixed(2)),
        status: 'pending_payment',
        payment: 'not_configured',
        createdAt: new Date().toISOString()
      };
      store.orders.unshift(created);
      return created;
    });
    res.status(201).json({ order, message: '订单已创建，当前尚未接入支付，请勿向客户显示支付成功。' });
  } catch (error) { next(error); }
});

app.post('/api/admin/login', requireSameOrigin, (req, res) => {
  const password = process.env.ADMIN_PASSWORD;
  if (!password || password.includes('请替换')) return res.status(503).json({ error: '请先在服务器配置强密码 ADMIN_PASSWORD' });
  const input = typeof req.body?.password === 'string' ? req.body.password : '';
  if (!safeEqual(input, password)) return res.status(401).json({ error: '密码错误' });
  const expiry = String(Date.now() + 8 * 60 * 60 * 1000);
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=${encodeURIComponent(`${expiry}.${signSession(expiry)}`)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${secure}`);
  res.json({ ok: true });
});

app.post('/api/admin/logout', requireSameOrigin, (req, res) => {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure}`);
  res.json({ ok: true });
});

app.get('/api/admin/session', requireAdmin, (req, res) => res.json({ authenticated: true }));

app.get('/api/admin/products', requireAdmin, async (req, res, next) => {
  try { res.json((await readStore()).products); } catch (error) { next(error); }
});

app.patch('/api/admin/products/:id', requireAdmin, requireSameOrigin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    const updated = await updateStore(store => {
      const product = store.products.find(entry => Number(entry.id) === id);
      if (!product) throw Object.assign(new Error('商品不存在'), { status: 404 });
      if (req.body?.stock !== undefined) {
        const stock = Number(req.body.stock);
        if (!Number.isSafeInteger(stock) || stock < 0 || stock > 10000000) throw Object.assign(new Error('库存必须是0到10000000之间的整数'), { status: 400 });
        product.stock = stock;
      }
      if (req.body?.price !== undefined) {
        const price = Number(req.body.price);
        if (!Number.isFinite(price) || price < 0 || price > 10000000) throw Object.assign(new Error('价格无效'), { status: 400 });
        product.price = Number(price.toFixed(2));
      }
      if (req.body?.title !== undefined) {
        const title = cleanText(req.body.title, 160);
        if (!title) throw Object.assign(new Error('商品名称不能为空'), { status: 400 });
        product.title = title;
      }
      return product;
    });
    res.json(updated);
  } catch (error) { next(error); }
});

app.get('/api/admin/orders', requireAdmin, async (req, res, next) => {
  try { res.json((await readStore()).orders); } catch (error) { next(error); }
});

app.post('/api/admin/orders/:id/cancel', requireAdmin, requireSameOrigin, async (req, res, next) => {
  try {
    const order = await updateStore(store => {
      const found = store.orders.find(entry => entry.id === req.params.id);
      if (!found) throw Object.assign(new Error('订单不存在'), { status: 404 });
      if (found.status !== 'pending_payment') throw Object.assign(new Error('仅未支付订单可以在此取消'), { status: 409 });
      for (const line of found.items) {
        const product = store.products.find(entry => Number(entry.id) === Number(line.productId));
        if (product) product.stock = Number(product.stock || 0) + Number(line.quantity || 0);
      }
      found.status = 'cancelled';
      found.cancelledAt = new Date().toISOString();
      return found;
    });
    res.json(order);
  } catch (error) { next(error); }
});

app.use(express.static(__dirname, { index: 'index.html' }));

app.use((error, req, res, next) => {
  console.error(error);
  if (res.headersSent) return next(error);
  res.status(error.status || 500).json({ error: error.status ? error.message : '服务器内部错误' });
});

async function start() {
  await loadEnvFile();
  sessionSecret = process.env.SESSION_SECRET;
  if (!sessionSecret || sessionSecret.includes('请替换') || sessionSecret.length < 32) {
    if (process.env.NODE_ENV === 'production') throw new Error('生产环境必须设置至少32位 SESSION_SECRET');
    sessionSecret = crypto.randomBytes(48).toString('hex');
    console.warn('SESSION_SECRET 未配置：本次运行使用临时随机值，重启后后台会话失效。');
  }
  await fs.mkdir(path.dirname(DATA_FILE), { recursive: true });
  try { await fs.access(DATA_FILE); } catch { await fs.writeFile(DATA_FILE, `${JSON.stringify(defaultStore(), null, 2)}\n`); }
  app.listen(PORT, () => console.log(`商城服务已启动：http://localhost:${PORT}`));
}

start().catch(error => { console.error(error); process.exit(1); });
