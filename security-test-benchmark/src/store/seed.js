const users = [
  {
    id: 'user-alice',
    tenantId: 'tenant-a',
    email: 'alice@example.test',
    role: 'support_agent',
    permissions: ['documents:read'],
  },
  {
    id: 'user-fran',
    tenantId: 'tenant-a',
    email: 'fran@example.test',
    role: 'finance_approver',
    permissions: ['documents:read', 'refunds:approve'],
  },
  {
    id: 'user-admin',
    tenantId: 'tenant-a',
    email: 'admin@example.test',
    role: 'admin',
    permissions: ['documents:read', 'users:write', 'refunds:approve'],
  },
  {
    id: 'user-bob',
    tenantId: 'tenant-b',
    email: 'bob@example.test',
    role: 'support_agent',
    permissions: ['documents:read'],
  },
];

const documents = [
  { id: 'doc-a-1', tenantId: 'tenant-a', ownerId: 'user-alice', title: 'Alice invoice', body: 'Invoice data for tenant A' },
  { id: 'doc-b-1', tenantId: 'tenant-b', ownerId: 'user-bob', title: 'Bob invoice', body: 'Invoice data for tenant B' },
];

const refunds = [
  { id: 'refund-a-1', tenantId: 'tenant-a', amount: 12900, status: 'pending', requestedBy: 'user-alice' },
  { id: 'refund-b-1', tenantId: 'tenant-b', amount: 4800, status: 'pending', requestedBy: 'user-bob' },
];

module.exports = { users, documents, refunds };
