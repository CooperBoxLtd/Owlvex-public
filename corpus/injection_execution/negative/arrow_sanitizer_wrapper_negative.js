const clean = (value) => sanitize(value);

export function findUser(db, input) {
    const safeName = clean(input);
    return db.query(`SELECT * FROM users WHERE name = '${safeName}'`);
}
