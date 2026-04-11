/**
 * SM-002 negative: app.set('debug', true) correctly guarded.
 *
 * The debug activation is inside `if (process.env.NODE_ENV !== 'production')`.
 * The invariant is satisfied — no finding expected.
 */
const express = require('express');
const app = express();

if (process.env.NODE_ENV !== 'production') {
  app.set('debug', true);
}

app.use(express.json());
app.get('/health', (req, res) => res.json({ ok: true }));
app.listen(process.env.PORT || 3000);
