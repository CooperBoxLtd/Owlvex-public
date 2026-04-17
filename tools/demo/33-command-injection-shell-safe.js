// Demo fixture 33 - Command execution with spawn() argument array
//
// The user value is passed as an argument, not embedded into shell syntax.
// Owlvex should stay quiet here.

const { spawn } = require('child_process');

function lookupAccount(req) {
    return spawn('grep', [req.query.username, '/var/app/accounts.txt'], { shell: false });
}
