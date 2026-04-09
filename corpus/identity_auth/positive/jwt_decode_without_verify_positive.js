export function readClaims(token) {
    return jwt.decode(token);
}
