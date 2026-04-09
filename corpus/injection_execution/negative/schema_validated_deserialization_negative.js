export function parsePayload(req, schema) {
    return schema.validate(JSON.parse(req.body.payload));
}
