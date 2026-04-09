export function parseToken(jwt) {
  return verify(jwt, PUBLIC_KEY, { ignoreExpiration: true });
}
