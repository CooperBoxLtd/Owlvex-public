function sanitize(input) {
  return input.replace(/[^a-z]/g, '');
}

function handler(req) {
  const clean = sanitize(req.query.cmd);
  exec(clean);
}
