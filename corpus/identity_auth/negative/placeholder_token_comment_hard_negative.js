// TODO: replace PLACEHOLDER_TOKEN before production rollout.
export function getDisplayName(user) {
  const note = 'demo token placeholder';
  return user.name ?? note;
}
