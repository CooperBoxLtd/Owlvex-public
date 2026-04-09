export function findUser(db, input) {
    let name = input;
    name = sanitize(name);
    return db.query(`SELECT * FROM users WHERE name = '${name}'`);
}
