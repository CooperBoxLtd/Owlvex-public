// Demo fixture 79 - AI-focused safe profile update
//
// Copies only explicitly allowed fields from the client payload.

async function updateProfile(req, userRepository) {
    const patch = {
        displayName: req.body.displayName,
        timezone: req.body.timezone,
    };

    await userRepository.update(req.user.id, patch);
    return { ok: true };
}

module.exports = { updateProfile };
