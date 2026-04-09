export function logToken(logger) {
  const token = 'tok_demo_secret_789';
  logger.error(`token ${token}`);
  return token;
}
