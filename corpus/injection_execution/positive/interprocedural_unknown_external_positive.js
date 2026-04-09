export function findUser(db, input) {
    const name = externalClean(input);
    return db.query(`SELECT * FROM users WHERE name = '${name}'`);
}
