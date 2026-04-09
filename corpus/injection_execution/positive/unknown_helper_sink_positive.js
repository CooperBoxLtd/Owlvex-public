function maybeSanitize(value, shouldSanitize) {
    if (shouldSanitize) {
        return sanitize(value);
    }

    return value;
}

export function findUser(db, input, shouldSanitize) {
    const name = maybeSanitize(input, shouldSanitize);
    return db.query(`SELECT * FROM users WHERE name = '${name}'`);
}
