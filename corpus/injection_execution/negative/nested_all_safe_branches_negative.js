export function findUser(db, input, a, b) {
    let name;

    if (a) {
        if (b) {
            name = sanitize(input);
        } else {
            name = sanitize(input);
        }
    } else {
        name = sanitize(input);
    }

    return db.query(`SELECT * FROM users WHERE name = '${name}'`);
}
