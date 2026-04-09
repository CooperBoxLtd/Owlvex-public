export function handleFailure(logger, res, error) {
  logger.error(error.message);
  return res.send(error.message);
}
