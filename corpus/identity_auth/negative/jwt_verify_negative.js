export function readClaims(token) {
    return jwt.verify(token, PUBLIC_KEY, { issuer: 'owlvex', audience: 'admin-ui' });
}
