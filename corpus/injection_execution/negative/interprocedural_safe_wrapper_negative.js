function clean(value) {
    return sanitize(value);
}

export function findUser(db, input) {
    const name = clean(input);
    return db.query(`SELECT * FROM users WHERE name = '${name}'`);
}
