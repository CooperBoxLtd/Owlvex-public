#!/usr/bin/env node

const [mode = 'overview', arg, arg2] = process.argv.slice(2);
const apiUrl = (process.env.OWLVEX_API_URL || 'https://owlvexdev-api.azurewebsites.net').replace(/\/+$/, '');
const adminKey = process.env.OWLVEX_ADMIN_KEY;

if (!adminKey) {
  console.error('Missing OWLVEX_ADMIN_KEY environment variable.');
  process.exit(1);
}

async function callJson(url) {
  const res = await fetch(url, {
    headers: {
      'X-Admin-Key': adminKey,
    },
  });
  const text = await res.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(`Invalid JSON response: ${text.slice(0, 200)}`);
  }

  if (!res.ok) {
    throw new Error(data?.detail || `HTTP ${res.status}`);
  }
  return data;
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'X-Admin-Key': adminKey,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(`Invalid JSON response: ${text.slice(0, 200)}`);
  }

  if (!res.ok) {
    throw new Error(data?.detail || `HTTP ${res.status}`);
  }
  return data;
}

function printOverview(data) {
  console.log(`Customers returned: ${data.count}`);
  for (const customer of data.customers) {
    const latestLicence = customer.licences?.[0];
    console.log('');
    console.log(`${customer.email}`);
    console.log(`  verified: ${customer.email_verified_at ? 'yes' : 'no'}`);
    console.log(`  pending plan: ${customer.pending_plan || 'none'}`);
    console.log(`  verification pending: ${customer.verification_pending ? 'yes' : 'no'}`);
    console.log(`  latest licence: ${latestLicence ? `${latestLicence.plan} (${latestLicence.is_active ? 'active' : 'inactive'})` : 'none'}`);
  }
}

function printCustomer(data) {
  console.log(JSON.stringify(data, null, 2));
}

async function main() {
  if (mode === 'overview') {
    const data = await callJson(`${apiUrl}/v1/admin/overview`);
    printOverview(data);
    return;
  }

  if (mode === 'customer') {
    if (!arg) {
      throw new Error('Usage: node tools/admin-db-view.mjs customer <email>');
    }
    const data = await callJson(`${apiUrl}/v1/admin/customer?email=${encodeURIComponent(arg)}`);
    printCustomer(data);
    return;
  }

  if (mode === 'resend-verification') {
    if (!arg) {
      throw new Error('Usage: node tools/admin-db-view.mjs resend-verification <email>');
    }
    const data = await postJson(`${apiUrl}/v1/admin/resend-verification`, { email: arg });
    console.log(JSON.stringify(data, null, 2));
    return;
  }

  if (mode === 'deactivate') {
    if (!arg) {
      throw new Error('Usage: node tools/admin-db-view.mjs deactivate <email> [plan]');
    }
    const data = await postJson(`${apiUrl}/v1/admin/licence/deactivate`, {
      email: arg,
      plan: arg2 || null,
    });
    console.log(JSON.stringify(data, null, 2));
    return;
  }

  if (mode === 'rotate') {
    if (!arg) {
      throw new Error('Usage: node tools/admin-db-view.mjs rotate <email> [plan]');
    }
    const data = await postJson(`${apiUrl}/v1/admin/licence/rotate`, {
      email: arg,
      plan: arg2 || null,
    });
    console.log(JSON.stringify(data, null, 2));
    return;
  }

  throw new Error('Usage: node tools/admin-db-view.mjs [overview|customer <email>|resend-verification <email>|deactivate <email> [plan]|rotate <email> [plan]]');
}

main().catch((error) => {
  console.error(`admin-db-view failed: ${error.message}`);
  process.exit(1);
});
