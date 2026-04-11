/**
 * SM-002 positive: app.set('debug', true) at module level.
 *
 * The file is env-aware (uses NODE_ENV to select port / log level) but the
 * debug activation is NOT wrapped in an env guard. It will be active in
 * production, leaking stack traces and internal routing information.
 */
const express = require('express');
const app = express();

const port = process.env.NODE_ENV === 'production' ? 80 : 3000;

app.use(express.json());

// BUG: debug enabled unconditionally
app.set('debug', true);

app.get('/health', (req, res) => res.json({ ok: true }));
app.listen(port);
