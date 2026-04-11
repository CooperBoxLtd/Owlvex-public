import { DeterministicScanner } from './deterministicScanner';

const scanner = new DeterministicScanner();

// ---------------------------------------------------------------------------
// Language gating
// ---------------------------------------------------------------------------
describe('DeterministicScanner — language gating', () => {
    it('returns no findings for unsupported languages', () => {
        const source = 'exec(`cmd ${input}`)';
        expect(scanner.scan(source, 'python')).toHaveLength(0);
        expect(scanner.scan(source, 'java')).toHaveLength(0);
        expect(scanner.scan(source, 'go')).toHaveLength(0);
    });

    it('returns findings for javascript', () => {
        const source = 'exec(`ls ${userInput}`)';
        expect(scanner.scan(source, 'javascript').length).toBeGreaterThan(0);
    });

    it('returns findings for typescript', () => {
        const source = 'exec(`ls ${userInput}`)';
        expect(scanner.scan(source, 'typescript').length).toBeGreaterThan(0);
    });

    it('returns findings for javascriptreact', () => {
        const source = 'exec(`ls ${userInput}`)';
        expect(scanner.scan(source, 'javascriptreact').length).toBeGreaterThan(0);
    });
});

// ---------------------------------------------------------------------------
// GR-001: Command / shell injection
// ---------------------------------------------------------------------------
describe('DeterministicScanner — GR-001 shell injection', () => {
    it('detects exec() with template literal interpolation', () => {
        const source = `
const { exec } = require('child_process');
function handler(req, res) {
  const filename = req.query.file;
  exec(\`cat \${filename}\`, (err, stdout) => {
    res.send(stdout);
  });
}`;
        const findings = scanner.scan(source, 'javascript');
        expect(findings).toHaveLength(1);
        expect(findings[0].ruleCode).toBe('GR-001');
        expect(findings[0].severity).toBe('HIGH');
        expect(findings[0].title).toBe('Command Injection');
        expect(findings[0].confidence).toBe(1);
        expect(findings[0].canonicalId).toBe('owlvex.issue.command_injection.001');
    });

    it('detects execSync() with template literal interpolation', () => {
        const source = `execSync(\`ls -la \${dir}\`)`;
        const findings = scanner.scan(source, 'javascript');
        expect(findings).toHaveLength(1);
        expect(findings[0].ruleCode).toBe('GR-001');
    });

    it('detects spawn() with template literal interpolation', () => {
        const source = `spawn(\`bash -c \${cmd}\`)`;
        const findings = scanner.scan(source, 'javascript');
        expect(findings).toHaveLength(1);
        expect(findings[0].ruleCode).toBe('GR-001');
    });

    it('detects spawnSync() with template literal interpolation', () => {
        const source = `spawnSync(\`grep \${pattern} /etc/passwd\`)`;
        const findings = scanner.scan(source, 'javascript');
        expect(findings).toHaveLength(1);
        expect(findings[0].ruleCode).toBe('GR-001');
    });

    it('does not flag exec() with a plain string literal', () => {
        const source = `exec('ls -la /tmp')`;
        expect(scanner.scan(source, 'javascript')).toHaveLength(0);
    });

    it('does not flag exec() with a template literal without interpolation', () => {
        const source = 'exec(`ls -la /tmp`)';
        expect(scanner.scan(source, 'javascript')).toHaveLength(0);
    });

    it('reports the correct line number', () => {
        const source = `// header\nconst x = 1;\nexec(\`ls \${input}\`);`;
        const findings = scanner.scan(source, 'javascript');
        expect(findings).toHaveLength(1);
        expect(findings[0].line).toBe(3);
    });

    it('detects multiple shell sinks in one file', () => {
        const source = [
            `exec(\`cat \${file}\`);`,
            `execSync(\`rm \${target}\`);`,
        ].join('\n');
        expect(scanner.scan(source, 'javascript')).toHaveLength(2);
    });

    it('assigns unique ids to each finding', () => {
        const source = [
            `exec(\`cat \${file}\`);`,
            `execSync(\`rm \${target}\`);`,
        ].join('\n');
        const findings = scanner.scan(source, 'javascript');
        expect(findings[0].id).not.toBe(findings[1].id);
    });
});

// ---------------------------------------------------------------------------
// SQ-001: SQL injection
// ---------------------------------------------------------------------------
describe('DeterministicScanner — SQ-001 SQL injection', () => {
    it('detects db.query() with template literal interpolation', () => {
        const source = `
const query = \`SELECT * FROM users WHERE id = '\${userId}'\`;
return db.query(query);`;
        const findings = scanner.scan(source, 'javascript');
        expect(findings).toHaveLength(1);
        expect(findings[0].ruleCode).toBe('SQ-001');
        expect(findings[0].severity).toBe('HIGH');
        expect(findings[0].title).toBe('SQL Injection');
        expect(findings[0].confidence).toBe(1);
        expect(findings[0].canonicalId).toBe('owlvex.issue.sql_injection.001');
    });

    it('detects inline template literal in db.query()', () => {
        const source = "db.query(`SELECT id FROM users WHERE name = '${username}'`)";
        const findings = scanner.scan(source, 'typescript');
        expect(findings).toHaveLength(1);
        expect(findings[0].ruleCode).toBe('SQ-001');
    });

    it('detects pool.query() with template literal interpolation', () => {
        const source = "pool.query(`SELECT * FROM orders WHERE user_id = '${id}'`)";
        expect(scanner.scan(source, 'javascript')).toHaveLength(1);
    });

    it('detects .execute() with template literal interpolation', () => {
        const source = "conn.execute(`UPDATE users SET role='admin' WHERE id=${id}`)";
        expect(scanner.scan(source, 'javascript')).toHaveLength(1);
    });

    it('does not flag parameterized query with string literal', () => {
        const source = "db.query('SELECT * FROM users WHERE id = $1', [userId])";
        expect(scanner.scan(source, 'javascript')).toHaveLength(0);
    });

    it('does not flag a constant query template with no interpolation', () => {
        const source = 'db.query(`SELECT COUNT(*) FROM users`)';
        expect(scanner.scan(source, 'javascript')).toHaveLength(0);
    });

    it('reports the correct line number for SQL sink', () => {
        const source = `const x = 1;\nconst y = 2;\ndb.query(\`SELECT \${col} FROM t\`);`;
        const findings = scanner.scan(source, 'javascript');
        expect(findings).toHaveLength(1);
        expect(findings[0].line).toBe(3);
    });
});

// ---------------------------------------------------------------------------
// SQ-005: SQL context mismatch — HTML sanitizer applied before SQL sink
// ---------------------------------------------------------------------------
describe('DeterministicScanner — SQ-005 SQL context mismatch', () => {
    it('detects HTML sanitizer applied before a SQL interpolation', () => {
        const source = `
function handler(db, username) {
  const cleaned = escapeHtml(username);
  const query = \`SELECT id FROM users WHERE username = '\${cleaned}'\`;
  return db.query(query);
}`;
        const findings = scanner.scan(source, 'javascript');
        expect(findings).toHaveLength(1);
        expect(findings[0].ruleCode).toBe('SQ-001');
        expect(findings[0].title).toContain('Ineffective HTML Sanitizer');
        expect(findings[0].explanation).toMatch(/html escaping does not/i);
    });

    it('detects htmlspecialchars as a non-SQL-safe sanitizer', () => {
        const source = `
const safe = htmlspecialchars(input);
db.query(\`SELECT * FROM t WHERE val = '\${safe}'\`);`;
        const findings = scanner.scan(source, 'javascript');
        expect(findings).toHaveLength(1);
        expect(findings[0].title).toContain('Ineffective HTML Sanitizer');
    });

    it('does not add context-mismatch label when no HTML sanitizer is present', () => {
        const source = "db.query(`SELECT * FROM users WHERE id = '${userId}'`)";
        const findings = scanner.scan(source, 'javascript');
        expect(findings).toHaveLength(1);
        expect(findings[0].title).toBe('SQL Injection');
    });
});

// ---------------------------------------------------------------------------
// Finding shape
// ---------------------------------------------------------------------------
describe('DeterministicScanner — finding shape', () => {
    it('populates all required finding fields', () => {
        const source = `exec(\`cmd \${x}\`)`;
        const findings = scanner.scan(source, 'javascript');
        expect(findings).toHaveLength(1);
        const f = findings[0];
        expect(f.id).toBeTruthy();
        expect(f.line).toBeGreaterThan(0);
        expect(f.lineEnd).toBeGreaterThan(0);
        expect(f.severity).toBeTruthy();
        expect(f.framework).toBe('OWASP');
        expect(f.ruleCode).toBeTruthy();
        expect(f.title).toBeTruthy();
        expect(f.explanation).toBeTruthy();
        expect(f.threat).toBeTruthy();
        expect(f.fix).toBeTruthy();
        expect(f.confidence).toBe(1);
        expect(f.canonicalId).toBeTruthy();
    });

    it('produces deterministic fields but unique ids per run', () => {
        const source = `exec(\`cmd \${x}\`)`;
        const first = scanner.scan(source, 'javascript');
        const second = scanner.scan(source, 'javascript');
        expect(first[0].line).toBe(second[0].line);
        expect(first[0].ruleCode).toBe(second[0].ruleCode);
        expect(first[0].id).not.toBe(second[0].id);
    });
});
