// Demo fixture 29 - Path traversal fixed with an identifier map
//
// User input is mapped to known-safe filenames before touching the filesystem.
// Owlvex should stay quiet here.

const path = require('path');

const SAFE_FILES = {
    invoice: 'invoice.pdf',
    statement: 'statement.pdf',
};

function downloadFile(req, res) {
    const selected = SAFE_FILES[req.query.file];
    if (!selected) {
        res.status(404).send('not found');
        return;
    }

    const fullPath = path.join('/var/app/uploads', selected);
    res.sendFile(fullPath);
}
