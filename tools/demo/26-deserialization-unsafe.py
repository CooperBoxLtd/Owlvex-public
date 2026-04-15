# Demo fixture 26 — Untrusted payload deserialized with pickle
#
# Not covered by the deterministic engine today.
# This is intended as an AI-only coverage example.

import pickle


def load_profile(request):
    return pickle.loads(request.body)
