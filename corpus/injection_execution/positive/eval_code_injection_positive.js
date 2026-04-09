export function runUserExpression(req) {
    const expression = req.query.expression;
    return eval(expression);
}
