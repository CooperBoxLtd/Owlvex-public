function escapeShellArg(input) {
  return input.replace(/[^a-z]/g, '');
}

const runner = exec;

function handler(req) {
  const clean = escapeShellArg(req.query.cmd);
  runner(clean);
}
