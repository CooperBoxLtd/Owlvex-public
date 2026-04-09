export function findUser(db, input, isInternal) {
    let name;

    if (isInternal) {
        name = sanitize(input);
    } else {
        name = sanitize(input);
    }

    return db.query(`SELECT * FROM users WHERE name = '${name}'`);
}
