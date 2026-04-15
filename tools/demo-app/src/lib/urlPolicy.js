const SAFE_REDIRECT_HOSTS = new Set(['app.owlvex.test', 'portal.owlvex.test']);
const SAFE_FETCH_HOSTS = new Set(['status.owlvex.test', 'api.partner.owlvex.test']);

function resolveSafeRedirect(target) {
  const parsed = new URL(target, 'https://app.owlvex.test');
  if (!SAFE_REDIRECT_HOSTS.has(parsed.host)) {
    throw new Error('redirect_target_blocked');
  }
  return parsed.toString();
}

function isAllowedOutboundUrl(target) {
  const parsed = new URL(target);
  return SAFE_FETCH_HOSTS.has(parsed.host);
}

module.exports = {
  resolveSafeRedirect,
  isAllowedOutboundUrl
};
