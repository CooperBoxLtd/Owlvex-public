import { DeterministicScanner } from './deterministicScanner';

const scanner = new DeterministicScanner();

interface EvidenceCase {
    name: string;
    language: string;
    source: string;
    expectedCanonicalIds: string[];
    expectedEvidenceTypes?: string[];
}

const cases: EvidenceCase[] = [
    {
        name: 'unsafe JS path traversal has source-flow-sink-guard evidence',
        language: 'javascript',
        source: `
const path = require('path');
const fs = require('fs');
function exportReport(req, res) {
  const filePath = path.join('/srv/app/exports', req.query.file);
  const report = fs.readFileSync(filePath, 'utf8');
  res.type('text/plain').send(report);
}`,
        expectedCanonicalIds: ['owlvex.issue.path_traversal.001'],
        expectedEvidenceTypes: ['path-traversal'],
    },
    {
        name: 'safe JS path traversal fix remains clean',
        language: 'javascript',
        source: `
const path = require('path');
const fs = require('fs');
const exportsDir = path.resolve('/srv/app/exports');
function resolveExportPath(requested) {
  if (typeof requested !== 'string' || requested.length === 0) return null;
  if (path.basename(requested) !== requested || path.extname(requested) !== '.txt') return null;
  const resolved = path.resolve(exportsDir, requested);
  const relative = path.relative(exportsDir, resolved);
  if (relative.startsWith('..') || path.isAbsolute(relative)) return null;
  return resolved;
}
function exportReport(req, res) {
  const filePath = resolveExportPath(req.query.file);
  if (!filePath) return res.status(400).json({ error: 'invalid_export' });
  const report = fs.readFileSync(filePath, 'utf8');
  res.type('text/plain').send(report);
}`,
        expectedCanonicalIds: [],
    },
    {
        name: 'unsafe JS SQL injection has source-flow-sink-guard evidence',
        language: 'javascript',
        source: `
async function loadUser(req, db) {
  const userId = req.query.id;
  return db.query(\`SELECT * FROM users WHERE id = \${userId}\`);
}`,
        expectedCanonicalIds: ['owlvex.issue.sql_injection.001'],
        expectedEvidenceTypes: ['sql-injection'],
    },
    {
        name: 'safe JS parameterized SQL remains clean',
        language: 'javascript',
        source: `
async function loadUser(req, db) {
  const userId = req.query.id;
  return db.query('SELECT * FROM users WHERE id = ?', [userId]);
}`,
        expectedCanonicalIds: [],
    },
    {
        name: 'unsafe Python SQL injection has source-flow-sink-guard evidence',
        language: 'python',
        source: `
def load_user(request, cursor):
    user_id = request.args.get("id")
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return cursor.execute(query)
`,
        expectedCanonicalIds: ['owlvex.issue.sql_injection.001'],
        expectedEvidenceTypes: ['sql-injection'],
    },
    {
        name: 'safe Python parameterized SQL remains clean',
        language: 'python',
        source: `
def load_user(request, cursor):
    user_id = request.args.get("id")
    return cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])
`,
        expectedCanonicalIds: [],
    },
    {
        name: 'unsafe Java SQL injection has source-flow-sink-guard evidence',
        language: 'java',
        source: `
class Users {
    ResultSet loadUser(HttpServletRequest request, Statement statement) throws Exception {
        String userId = request.getParameter("id");
        String query = "SELECT * FROM users WHERE id = " + userId;
        return statement.executeQuery(query);
    }
}
`,
        expectedCanonicalIds: ['owlvex.issue.sql_injection.001'],
        expectedEvidenceTypes: ['sql-injection'],
    },
    {
        name: 'safe Java prepared statement remains clean',
        language: 'java',
        source: `
class Users {
    ResultSet loadUser(HttpServletRequest request, Connection connection) throws Exception {
        String userId = request.getParameter("id");
        PreparedStatement statement = connection.prepareStatement("SELECT * FROM users WHERE id = ?");
        statement.setString(1, userId);
        return statement.executeQuery();
    }
}
`,
        expectedCanonicalIds: [],
    },
    {
        name: 'unsafe C# SQL injection has source-flow-sink-guard evidence',
        language: 'csharp',
        source: `
class Users {
    object LoadUser(SqlConnection connection) {
        var userId = Request.Query["id"];
        var query = "SELECT * FROM users WHERE id = " + userId;
        return new SqlCommand(query, connection);
    }
}
`,
        expectedCanonicalIds: ['owlvex.issue.sql_injection.001'],
        expectedEvidenceTypes: ['sql-injection'],
    },
    {
        name: 'safe C# parameterized SQL remains clean',
        language: 'csharp',
        source: `
class Users {
    object LoadUser(SqlConnection connection) {
        var userId = Request.Query["id"];
        var command = new SqlCommand("SELECT * FROM users WHERE id = @id", connection);
        command.Parameters.AddWithValue("@id", userId);
        return command;
    }
}
`,
        expectedCanonicalIds: [],
    },
    {
        name: 'unsafe Go SQL injection has source-flow-sink-guard evidence',
        language: 'go',
        source: `
package demo

func loadUser(r *http.Request, db *sql.DB) (*sql.Rows, error) {
    id := r.URL.Query().Get("id")
    query := "SELECT * FROM users WHERE id = " + id
    return db.Query(query)
}
`,
        expectedCanonicalIds: ['owlvex.issue.sql_injection.001'],
        expectedEvidenceTypes: ['sql-injection'],
    },
    {
        name: 'safe Go parameterized SQL remains clean',
        language: 'go',
        source: `
package demo

func loadUser(r *http.Request, db *sql.DB) (*sql.Rows, error) {
    id := r.URL.Query().Get("id")
    return db.Query("SELECT * FROM users WHERE id = ?", id)
}
`,
        expectedCanonicalIds: [],
    },
    {
        name: 'unsafe Python path traversal has source-flow-sink-guard evidence',
        language: 'python',
        source: `
import os
from flask import request

def export_report():
    filename = request.args.get("file")
    target = os.path.join("/srv/app/exports", filename)
    return open(target, "r").read()
`,
        expectedCanonicalIds: ['owlvex.issue.path_traversal.001'],
        expectedEvidenceTypes: ['path-traversal'],
    },
    {
        name: 'safe Python path traversal fix remains clean',
        language: 'python',
        source: `
import os
from flask import request

def export_report():
    base_dir = os.path.abspath("/srv/app/exports")
    requested = request.args.get("file")
    candidate = os.path.abspath(os.path.join(base_dir, requested))
    if not candidate.startswith(base_dir + os.sep):
        return ("invalid", 400)
    return open(candidate, "r").read()
`,
        expectedCanonicalIds: [],
    },
    {
        name: 'unsafe Java path traversal has source-flow-sink-guard evidence',
        language: 'java',
        source: `
import java.nio.file.*;

class Reports {
    String exportReport(HttpServletRequest request) throws Exception {
        String filename = request.getParameter("file");
        Path target = Paths.get("/srv/app/exports", filename);
        return Files.readString(target);
    }
}
`,
        expectedCanonicalIds: ['owlvex.issue.path_traversal.001'],
        expectedEvidenceTypes: ['path-traversal'],
    },
    {
        name: 'safe Java path traversal fix remains clean',
        language: 'java',
        source: `
import java.nio.file.*;

class Reports {
    String exportReport(HttpServletRequest request) throws Exception {
        Path base = Paths.get("/srv/app/exports").toAbsolutePath().normalize();
        String filename = request.getParameter("file");
        Path target = base.resolve(filename).normalize();
        if (!target.startsWith(base)) {
            throw new IllegalArgumentException("invalid");
        }
        return Files.readString(target);
    }
}
`,
        expectedCanonicalIds: [],
    },
    {
        name: 'unsafe C# path traversal has source-flow-sink-guard evidence',
        language: 'csharp',
        source: `
using System.IO;

class Reports {
    string ExportReport() {
        var filename = Request.Query["file"];
        var target = Path.Combine("/srv/app/exports", filename);
        return File.ReadAllText(target);
    }
}
`,
        expectedCanonicalIds: ['owlvex.issue.path_traversal.001'],
        expectedEvidenceTypes: ['path-traversal'],
    },
    {
        name: 'safe C# path traversal fix remains clean',
        language: 'csharp',
        source: `
using System.IO;

class Reports {
    string ExportReport() {
        var baseDir = Path.GetFullPath("/srv/app/exports");
        var filename = Request.Query["file"];
        var target = Path.GetFullPath(Path.Combine(baseDir, filename));
        if (!target.StartsWith(baseDir + Path.DirectorySeparatorChar)) {
            throw new InvalidOperationException("invalid");
        }
        return File.ReadAllText(target);
    }
}
`,
        expectedCanonicalIds: [],
    },
    {
        name: 'unsafe Go path traversal has source-flow-sink-guard evidence',
        language: 'go',
        source: `
package demo

import (
    "net/http"
    "os"
    "path/filepath"
)

func exportReport(r *http.Request) ([]byte, error) {
    name := r.URL.Query().Get("file")
    target := filepath.Join("/srv/app/exports", name)
    return os.ReadFile(target)
}
`,
        expectedCanonicalIds: ['owlvex.issue.path_traversal.001'],
        expectedEvidenceTypes: ['path-traversal'],
    },
    {
        name: 'safe Go path traversal fix remains clean',
        language: 'go',
        source: `
package demo

import (
    "net/http"
    "os"
    "path/filepath"
    "strings"
)

func exportReport(r *http.Request) ([]byte, error) {
    base := "/srv/app/exports"
    name := r.URL.Query().Get("file")
    target := filepath.Clean(filepath.Join(base, name))
    if !strings.HasPrefix(target, base + string(os.PathSeparator)) {
        return nil, http.ErrAbortHandler
    }
    return os.ReadFile(target)
}
`,
        expectedCanonicalIds: [],
    },
    {
        name: 'unsafe client-controlled filter has source-flow-sink-guard evidence',
        language: 'javascript',
        source: `
function matchesFilter(user, filter) {
  return Object.entries(filter).every(([key, value]) => user[key] === value);
}
router.post('/users/search-unsafe', requireAdmin, (req, res) => {
  const filter = req.body && typeof req.body.filter === 'object' && req.body.filter !== null ? req.body.filter : {};
  const results = fakeUsers.filter(user => matchesFilter(user, filter));
  res.json({ count: results.length, results });
});`,
        expectedCanonicalIds: ['owlvex.issue.nosql_injection.001'],
        expectedEvidenceTypes: ['client-controlled-query-filter'],
    },
    {
        name: 'server-built user filter remains clean',
        language: 'javascript',
        source: `
router.post('/users/search-safe', requireAdmin, (req, res) => {
  const filter = {};
  if (typeof req.body.email === 'string') filter.email = req.body.email;
  if (typeof req.body.role === 'string' && ['user', 'admin'].includes(req.body.role)) filter.role = req.body.role;
  const results = fakeUsers.filter(user => matchesFilter(user, filter));
  res.json({ count: results.length, results });
});`,
        expectedCanonicalIds: [],
    },
];

describe('Engine evidence regression gate', () => {
    it.each(cases)('$name', testCase => {
        const findings = scanner.scan(testCase.source, testCase.language);
        expect(findings.map(finding => finding.canonicalId).sort()).toEqual(testCase.expectedCanonicalIds.sort());

        if (testCase.expectedEvidenceTypes?.length) {
            expect(findings.map(finding => finding.evidenceContract?.issueType).sort()).toEqual(testCase.expectedEvidenceTypes.sort());
            for (const finding of findings) {
                expect(finding.evidenceContract).toMatchObject({
                    verdict: 'confirmed',
                    guard: {
                        status: 'missing',
                    },
                });
                expect(finding.evidenceContract?.source?.expression).toBeTruthy();
                expect(finding.evidenceContract?.sink?.expression).toBeTruthy();
                expect(finding.evidenceContract?.rationale).toBeTruthy();
            }
        }
    });
});
