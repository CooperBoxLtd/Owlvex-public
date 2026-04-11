function sanitize(input) {
  return input.replace(/[^a-z]/g, '');
}

function handler(req, isAdmin) {
  let cmd;

  if (isAdmin) {
    cmd = "ls";
  } else {
    cmd = req.query.cmd;
  }

  const clean = sanitize(cmd);
  exec(clean);
}
