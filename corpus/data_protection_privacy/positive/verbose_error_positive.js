export function handleError(error, res) {
  res.status(500).send(error.message);
}
