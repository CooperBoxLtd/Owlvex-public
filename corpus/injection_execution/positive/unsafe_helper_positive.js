function clean(value) {
    return value.trim();
}

export function findUser(db, input) {
    const maybeSafe = clean(input);
    return db.query(`SELECT * FROM users WHERE name = '${maybeSafe}'`);
}
