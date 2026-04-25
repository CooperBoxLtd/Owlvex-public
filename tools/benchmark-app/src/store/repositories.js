const { users, documents, refunds } = require('./seed');

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function createRepositories() {
  const state = {
    users: clone(users),
    documents: clone(documents),
    refunds: clone(refunds),
    audit: [],
    importedNotes: [],
  };

  return {
    users: {
      findById(id) {
        return state.users.find((user) => user.id === id) || null;
      },
      updateRole(userId, role) {
        const user = state.users.find((candidate) => candidate.id === userId);
        if (!user) return null;
        user.role = role;
        return user;
      },
      updateEmail(userId, email) {
        const user = state.users.find((candidate) => candidate.id === userId);
        if (!user) return null;
        user.email = email;
        return user;
      },
    },
    documents: {
      findById(documentId) {
        return state.documents.find((document) => document.id === documentId) || null;
      },
      findForTenant(documentId, tenantId) {
        return state.documents.find((document) => document.id === documentId && document.tenantId === tenantId) || null;
      },
    },
    refunds: {
      findForTenant(refundId, tenantId) {
        return state.refunds.find((refund) => refund.id === refundId && refund.tenantId === tenantId) || null;
      },
      approve(refundId, approvedBy) {
        const refund = state.refunds.find((candidate) => candidate.id === refundId);
        if (!refund) return null;
        refund.status = 'approved';
        refund.approvedBy = approvedBy;
        return refund;
      },
      approveForTenant(refundId, tenantId, approvedBy) {
        const refund = state.refunds.find((candidate) => candidate.id === refundId && candidate.tenantId === tenantId);
        if (!refund) return null;
        refund.status = 'approved';
        refund.approvedBy = approvedBy;
        return refund;
      },
    },
    audit: {
      write(event) {
        state.audit.push({ ...event, at: new Date().toISOString() });
      },
    },
    imports: {
      addCustomerNote(note) {
        state.importedNotes.push(note);
        return note;
      },
    },
  };
}

module.exports = { createRepositories };
