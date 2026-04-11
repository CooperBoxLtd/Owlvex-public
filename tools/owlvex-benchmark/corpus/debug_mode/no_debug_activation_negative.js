/**
 * SM-002 negative: env-aware file with no debug activation.
 *
 * NODE_ENV is used for configuration but no app.set('debug', ...) or
 * app.enable('debug') call is present. Nothing to flag.
 */
const express = require('express');
const app = express();

const isProd = process.env.NODE_ENV === 'production';
const logLevel = isProd ? 'error' : 'debug';

app.use(express.json());
app.get('/health', (req, res) => res.json({ ok: true, env: process.env.NODE_ENV }));
app.listen(isProd ? 80 : 3000);
