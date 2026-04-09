export function getAuthHeader() {
  const header = 'Bearer ' + process.env.API_TOKEN;
  return header;
}
