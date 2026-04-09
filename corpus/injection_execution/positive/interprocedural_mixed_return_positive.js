function clean(value, shouldSanitize) {
    return shouldSanitize ? sanitize(value) : value;
}

export function findUser(db, input, shouldSanitize) {
    const name = clean(input, shouldSanitize);
    return db.query(`SELECT * FROM users WHERE name = '${name}'`);
}
