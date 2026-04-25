function auditSafe(audit, event) {
  audit.write({
    type: event.type,
    actorId: event.actorId,
    targetId: event.targetId,
    outcome: event.outcome,
  });
}

function auditUnsafe(audit, event) {
  audit.write(event);
}

module.exports = { auditSafe, auditUnsafe };
