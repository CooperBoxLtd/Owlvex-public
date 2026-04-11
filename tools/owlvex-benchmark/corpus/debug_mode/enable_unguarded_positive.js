/**
 * SM-002 positive: app.enable('debug') without env guard.
 *
 * Process.env is referenced for port configuration, confirming env-awareness.
 * The enable('debug') call is at the top level and has no surrounding
 * NODE_ENV condition.
 */
const express = require('express');
const app = express();

const port = process.env.PORT || 3000;

app.enable('debug');

app.use(express.json());
app.get('/', (req, res) => res.send('ok'));
app.listen(port);
