// Demo fixture 25 — JWT verified with explicit algorithm, issuer, and audience checks
//
// Companion to 24. The token is rejected unless verification constraints pass.

function readClaims(token, jwt) {
    return jwt.verify(token, process.env.JWT_PUBLIC_KEY, {
        algorithms: ['RS256'],
        issuer: 'https://issuer.example.com',
        audience: 'owlvex-demo',
    });
}
