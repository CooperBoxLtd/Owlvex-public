# Demo fixture 44 - Unsafe Python JWT decoding

import jwt


def parse_token(token):
    return jwt.decode(token, options={"verify_signature": False})
