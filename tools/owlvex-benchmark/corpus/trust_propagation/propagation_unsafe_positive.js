import { exec } from 'child_process';

export function handler(req) {
  const input = req.query.user;
  const copy = input;
  const final = copy;

  exec(final);
}
