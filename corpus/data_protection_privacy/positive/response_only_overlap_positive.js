export function sendFailure(res, error) {
  return res.send(error.message);
}
