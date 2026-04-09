// logger.error(error.message)
export function sendFailure(res, err) {
  return res.send(err.message);
}
