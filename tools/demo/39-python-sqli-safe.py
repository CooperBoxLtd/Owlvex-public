# Demo fixture 39 - Safe Python parameterized SQL


def load_user(cursor, request):
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])
