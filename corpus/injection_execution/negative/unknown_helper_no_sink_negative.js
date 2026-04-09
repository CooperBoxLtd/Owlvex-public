function maybeSanitize(value, shouldSanitize) {
    if (shouldSanitize) {
        return sanitize(value);
    }

    return value;
}

export function previewUser(input, shouldSanitize) {
    const name = maybeSanitize(input, shouldSanitize);
    return `Preview:${name}`;
}
