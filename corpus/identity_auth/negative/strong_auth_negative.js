export function validate(password, limiter, mfaRequired) {
  if (password.length < 14) throw new Error('weak');
  limiter.consume();
  if (!mfaRequired) throw new Error('mfa required');
  return true;
}
