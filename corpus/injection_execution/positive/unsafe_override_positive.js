export function findUser(db, input) {
    let name = sanitize(input);
    name = input;
    return db.query(`SELECT * FROM users WHERE name = '${name}'`);
}
