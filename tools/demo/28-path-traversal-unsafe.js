// Demo fixture 28 - Path traversal through user-controlled filename
//
// The requested filename is joined directly into a filesystem path.
// Owlvex should flag this as path traversal.

const path = require('path');

function downloadFile(req, res) {
    const fullPath = path.join('/var/app/uploads', req.query.file);
    res.sendFile(fullPath);
}
