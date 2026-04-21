# Demo fixture 26 — Untrusted payload deserialized with pickle
#
# Covered by the deterministic engine.
# This fixture is part of the trusted deserialization benchmark surface.

import pickle


def load_profile(request):
    return pickle.loads(request.body)
