// Never send error.message to clients in production.
export function safeNotice() {
  return 'handled';
}
