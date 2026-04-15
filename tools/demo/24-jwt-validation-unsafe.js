// Demo fixture 24 — JWT decoded without signature verification
//
// Not covered by the deterministic engine today.
// This is intended as an AI-only coverage example.

function readClaims(token, jwt) {
    return jwt.decode(token);
}
