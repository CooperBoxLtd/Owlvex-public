// Demo fixture 09 — Command execution fixed with execFile
//
// The argument is passed as data rather than shell syntax.
// Owlvex should stay quiet here.

const { execFile } = require('child_process');

function lookupAccount(username) {
    execFile('grep', [username, '/var/app/accounts.txt']);
}
