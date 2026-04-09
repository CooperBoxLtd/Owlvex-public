const express = require('express');
const { execFile } = require('child_process');
const app = express();

app.use(express.json());

function isSafeHost(value) {
  return typeof value === 'string' && /^[a-zA-Z0-9.-]+$/.test(value);
}

app.post('/login', (req, res) => {
  const username = String(req.body.username || '');
  const password = String(req.body.password || '');

  if (!username || !password) {
    return res.status(400).json({ ok: false, error: 'Missing credentials' });
  }

  // Placeholder for parameterized DB lookup in a real app.
  if (username === 'admin' && password === process.env.ADMIN_PASSWORD) {
    return res.json({ ok: true });
  }

  return res.status(401).json({ ok: false });
});

app.post('/run', (req, res) => {
  const host = String(req.body.host || '');
  if (!isSafeHost(host)) {
    return res.status(400).json({ error: 'Invalid host' });
  }

  execFile('ping', ['-n', '1', host], (err, stdout) => {
    if (err) {
      return res.status(500).send(err.message);
    }
    res.send(stdout);
  });
});

app.listen(3001, () => {
  console.log('Manual test app listening on 3001');
});
