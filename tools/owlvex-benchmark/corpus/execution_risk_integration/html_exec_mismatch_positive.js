function escapeHtml(input) {
  return input.replace(/[<>]/g, '');
}

function handler(req) {
  const clean = escapeHtml(req.query.cmd);
  exec(clean);
}
