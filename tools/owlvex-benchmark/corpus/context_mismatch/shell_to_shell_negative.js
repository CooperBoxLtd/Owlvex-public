function escapeShellArg(input) {
  return input.replace(/[^a-z]/g, '');
}

function handler(req) {
  const clean = escapeShellArg(req.query.cmd);
  exec(clean);
}
