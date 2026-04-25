const TRUSTED_PARTNERS = new Map([
  ['billing', 'https://billing.partner.example/status'],
  ['crm', 'https://crm.partner.example/profile'],
]);

function resolvePartnerUrl(partnerId) {
  const url = TRUSTED_PARTNERS.get(partnerId);
  if (!url) {
    throw new Error('unknown_partner');
  }
  return url;
}

async function fetchAllowedPartner(partnerId, fetchImpl = fetch) {
  const url = resolvePartnerUrl(partnerId);
  return fetchImpl(url, { method: 'GET', redirect: 'error' });
}

module.exports = { resolvePartnerUrl, fetchAllowedPartner };
