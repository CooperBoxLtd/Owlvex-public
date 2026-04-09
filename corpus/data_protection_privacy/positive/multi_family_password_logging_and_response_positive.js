export function handleFailure(logger, res, error) {
  const password = 'P@ssw0rd-demo';
  logger.error(error.message);
  return res.send(error.message || password);
}
