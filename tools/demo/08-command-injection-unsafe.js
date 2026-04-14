// Demo fixture 08 — Command injection via shell-parsed template literal
//
// The username value is embedded directly into a shell command string.
// Owlvex should flag this as GR-001.

const { exec } = require('child_process');

function lookupAccount(username) {
    exec(`grep "${username}" /var/app/accounts.txt`);
}
