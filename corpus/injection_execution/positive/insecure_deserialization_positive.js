export function parsePayload(req) {
    return yaml.load(req.body.payload);
}
