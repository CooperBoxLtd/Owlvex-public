// Demo fixture 32 - Command injection through spawn() with shell:true
//
// The command string is still shell-parsed, so interpolation remains dangerous.
// Owlvex should flag this as deterministic command injection.

const { spawn } = require('child_process');

function lookupAccount(req) {
    return spawn(`grep ${req.query.username} /var/app/accounts.txt`, [], { shell: true });
}
