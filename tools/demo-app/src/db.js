const documents = [
  { id: 'doc-100', ownerId: 'user-1', tenantId: 'tenant-a', title: 'Quarterly plan' },
  { id: 'doc-200', ownerId: 'user-2', tenantId: 'tenant-b', title: 'Payroll export' }
];

const users = [
  { id: 'user-1', tenantId: 'tenant-a', email: 'alice@tenant-a.test' },
  { id: 'user-2', tenantId: 'tenant-b', email: 'bob@tenant-b.test' }
];

function getDocumentById(id) {
  return documents.find((doc) => doc.id === id);
}

function getDocumentForUser(id, userId) {
  return documents.find((doc) => doc.id === id && doc.ownerId === userId);
}

function getDocumentForTenant(id, tenantId) {
  return documents.find((doc) => doc.id === id && doc.tenantId === tenantId);
}

function findUsersByEmailUnsafe(email) {
  return {
    sql: `SELECT id, email FROM users WHERE email = '${email}'`,
    rows: users.filter((user) => user.email === email)
  };
}

function findUsersByEmailSafe(email) {
  return {
    sql: 'SELECT id, email FROM users WHERE email = ?',
    params: [email],
    rows: users.filter((user) => user.email === email)
  };
}

module.exports = {
  getDocumentById,
  getDocumentForUser,
  getDocumentForTenant,
  findUsersByEmailUnsafe,
  findUsersByEmailSafe
};
