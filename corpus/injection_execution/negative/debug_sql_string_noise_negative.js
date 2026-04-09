export function renderDebugHelp(input) {
  const example = "SELECT * FROM users WHERE id = '" + input + "'";
  return `Example query: ${example}`;
}
