function normalize(value) {
    return value.trim();
}

export function findUser(db, input, isInternal) {
    let name;

    if (isInternal) {
        name = sanitize(input);
    } else {
        name = normalize(input);
    }

    return db.query(`SELECT * FROM users WHERE name = '${name}'`);
}
