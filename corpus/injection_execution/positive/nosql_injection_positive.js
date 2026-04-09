export async function searchUsers(users, filter) {
  return users.find(filter);
}
