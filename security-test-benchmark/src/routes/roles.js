const express = require('express');
const { requireUser } = require('../middleware/auth');
const { ALLOWED_ROLES, canAssignRole } = require('../policies/accessPolicy');

function createRoleRouter(repositories) {
  const router = express.Router();

  router.post('/:userId/role-unsafe', requireUser, async (req, res) => {
    const updated = repositories.users.updateRole(req.params.userId, req.body.role);
    res.json({ user: updated });
  });

  router.post('/:userId/role-safe', requireUser, async (req, res) => {
    const targetUser = repositories.users.findById(req.params.userId);
    const nextRole = String(req.body.role || '');
    if (!ALLOWED_ROLES.has(nextRole) || !canAssignRole(req.user, targetUser, nextRole)) {
      res.status(403).json({ error: 'forbidden' });
      return;
    }

    const updated = repositories.users.updateRole(targetUser.id, nextRole);
    res.json({ user: updated });
  });

  return router;
}

module.exports = { createRoleRouter };
