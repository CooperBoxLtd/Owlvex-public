function clean(value) {
    return value;
}

export function findUser(db, input) {
    const name = clean(input);
    return db.query(`SELECT * FROM users WHERE name = '${name}'`);
}
