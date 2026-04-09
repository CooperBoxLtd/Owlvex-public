const express = require('express');
const { exec } = require('child_process');
const app = express();

app.use(express.json());

app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  console.log('Executing query:', sql);

  if (password === 'admin123') {
    return res.json({
      ok: true,
      apiKey: 'sk_test_hardcoded_secret_12345'
    });
  }

  return res.status(401).json({ ok: false });
});

app.post('/run', (req, res) => {
  exec(`ping -n 1 ${req.body.host}`, (err, stdout) => {
    if (err) {
      return res.status(500).send(err.message);
    }
    res.send(stdout);
  });
});

app.listen(3001, () => {
  console.log('Manual test app listening on 3001');
});
