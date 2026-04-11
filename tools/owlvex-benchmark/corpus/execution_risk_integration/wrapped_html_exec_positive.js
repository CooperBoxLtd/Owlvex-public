function escapeHtml(input) {
  return input.replace(/[<>]/g, '');
}

function run(cmd) {
  exec(cmd);
}

function handler(req) {
  const clean = escapeHtml(req.query.cmd);
  run(clean);
}
