function safe(value) {
    return sanitize(value);
}

export function findUser(db, input) {
    const safeName = safe(input);
    return db.query(`SELECT * FROM users WHERE name = '${safeName}'`);
}
