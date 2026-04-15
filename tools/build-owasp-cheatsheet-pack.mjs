import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');

const cheatSheetMeta = {
  'OWASP Authentication Cheat Sheet': {
    slug: 'Authentication_Cheat_Sheet',
    focus: 'Authentication policy, credential handling, and brute-force resistance.',
    common_actions: ['Require strong verification rules.', 'Add lockout or rate limits on auth paths.'],
    avoid: ['Treating the UI as the security boundary.'],
  },
  'OWASP Authorization Cheat Sheet': {
    slug: 'Authorization_Cheat_Sheet',
    focus: 'Server-side authorization enforcement and privilege boundaries.',
    common_actions: ['Enforce explicit policy checks.', 'Scope every sensitive action to the authenticated principal.'],
    avoid: ['Assuming authentication alone is enough authorization.'],
  },
  'OWASP Cross Origin Resource Sharing Cheat Sheet': {
    slug: 'Cross_Origin_Resource_Sharing_Cheat_Sheet',
    source_slug: 'REST_Security_Cheat_Sheet',
    focus: 'Trusted-origin allow-lists, credential use, and browser-enforced cross-origin boundaries.',
    common_actions: ['Allow only explicit origins.', 'Review credentialed requests separately from public resources.'],
    avoid: ['Using wildcard origin settings on sensitive APIs.'],
    source_note: 'Nearest official OWASP cheat sheet source is the REST Security Cheat Sheet CORS guidance.',
  },
  'OWASP Cross Site Scripting Prevention Cheat Sheet': {
    slug: 'Cross_Site_Scripting_Prevention_Cheat_Sheet',
    focus: 'Context-aware output encoding, templating safety, and safe DOM rendering.',
    common_actions: ['Encode for the output context.', 'Prefer safe templating APIs over raw HTML insertion.'],
    avoid: ['Relying on a single generic sanitizer for every context.'],
  },
  'OWASP Cross-Site Request Forgery Prevention Cheat Sheet': {
    slug: 'Cross-Site_Request_Forgery_Prevention_Cheat_Sheet',
    focus: 'CSRF tokens, same-site controls, and state-changing browser requests.',
    common_actions: ['Require anti-CSRF tokens on state changes.', 'Use same-site protections where appropriate.'],
    avoid: ['Assuming authentication cookies alone prevent CSRF.'],
  },
  'OWASP Cryptographic Storage Cheat Sheet': {
    slug: 'Cryptographic_Storage_Cheat_Sheet',
    focus: 'Safe cryptographic primitives, modes, IVs, and secret storage decisions.',
    common_actions: ['Use modern authenticated encryption.', 'Generate unique IVs/nonces with secure randomness.'],
    avoid: ['Using deprecated algorithms or insecure modes.'],
  },
  'OWASP Deserialization Cheat Sheet': {
    slug: 'Deserialization_Cheat_Sheet',
    focus: 'Unsafe object reconstruction, gadget chains, and untrusted serialized input.',
    common_actions: ['Use safe formats and strict schemas.', 'Reject untrusted object graphs or type hints.'],
    avoid: ['Deserializing attacker-controlled payloads into rich object models.'],
  },
  'OWASP Error Handling Cheat Sheet': {
    slug: 'Error_Handling_Cheat_Sheet',
    focus: 'Generic client errors, protected diagnostics, and internal-only debug detail.',
    common_actions: ['Return generic error messages.', 'Keep stack traces and internals out of public responses.'],
    avoid: ['Leaking exception detail to untrusted callers.'],
  },
  'OWASP File Upload Cheat Sheet': {
    slug: 'File_Upload_Cheat_Sheet',
    focus: 'Upload validation, storage isolation, and content handling safety.',
    common_actions: ['Restrict file types and size.', 'Store uploads outside executable paths.'],
    avoid: ['Trusting file extensions alone.'],
  },
  'OWASP Input Validation Cheat Sheet': {
    slug: 'Input_Validation_Cheat_Sheet',
    focus: 'Allow-listing, bounded inputs, and rejecting attacker-controlled malformed data early.',
    common_actions: ['Validate structure and size at boundaries.', 'Prefer allow-lists to weak deny-lists.'],
    avoid: ['Relying on partial regex checks as complete safety controls.'],
  },
  'OWASP JSON Web Token Cheat Sheet for Java': {
    slug: 'JSON_Web_Token_for_Java_Cheat_Sheet',
    focus: 'JWT verification, algorithm restrictions, claims validation, and token handling pitfalls.',
    common_actions: ['Verify issuer, audience, expiry, and allowed algorithms.', 'Reject unsigned or weakly validated tokens.'],
    avoid: ['Trusting token presence without full verification.'],
  },
  'OWASP LDAP Injection Prevention Cheat Sheet': {
    slug: 'LDAP_Injection_Prevention_Cheat_Sheet',
    focus: 'Safe directory query construction and escaping of LDAP filters.',
    common_actions: ['Use safe LDAP APIs.', 'Escape filter input and constrain query structure.'],
    avoid: ['Concatenating user input into LDAP filters.'],
  },
  'OWASP Logging Cheat Sheet': {
    slug: 'Logging_Cheat_Sheet',
    focus: 'Operational logging without sensitive-data leakage or log injection.',
    common_actions: ['Log only necessary operational data.', 'Sanitize user-controlled log fields.'],
    avoid: ['Logging secrets, tokens, or raw control characters.'],
  },
  'OWASP Mass Assignment Cheat Sheet': {
    slug: 'Mass_Assignment_Cheat_Sheet',
    focus: 'Binding controls, DTOs, and explicit field allow-lists for object updates.',
    common_actions: ['Use DTOs or explicit allow-lists.', 'Keep privileged fields off public bind paths.'],
    avoid: ['Binding request bodies directly into domain objects.'],
  },
  'OWASP NoSQL Security Cheat Sheet': {
    slug: 'NoSQL_Security_Cheat_Sheet',
    focus: 'Operator injection, query object validation, and safe NoSQL filtering.',
    common_actions: ['Validate query objects strictly.', 'Prevent client-controlled operators from reaching filters.'],
    avoid: ['Passing raw query objects from clients into the database layer.'],
  },
  'OWASP OS Command Injection Defense Cheat Sheet': {
    slug: 'OS_Command_Injection_Defense_Cheat_Sheet',
    focus: 'Removing shell-string execution and validating any required process arguments.',
    common_actions: ['Replace shell execution with safe APIs.', 'Allow-list every remaining argument.'],
    avoid: ['Escaping a few shell characters while keeping string-built commands.'],
  },
  'OWASP Path Traversal Cheat Sheet': {
    slug: 'Path_Traversal_Cheat_Sheet',
    source_slug: 'Symfony_Cheat_Sheet',
    focus: 'Filesystem boundary enforcement, safe base paths, and path normalization.',
    common_actions: ['Resolve against a fixed base path.', 'Reject traversal outside allowed roots.'],
    avoid: ['Stripping ../ without canonical boundary checks.'],
    source_note: 'Nearest official OWASP cheat sheet source is the Symfony Cheat Sheet directory traversal guidance.',
  },
  'OWASP Prototype Pollution Prevention Cheat Sheet': {
    slug: 'Prototype_Pollution_Prevention_Cheat_Sheet',
    focus: 'Dangerous object keys, safe merge behavior, and defensive schema validation.',
    common_actions: ['Reject __proto__-style keys.', 'Use safe merge utilities and strict schemas.'],
    avoid: ['Blindly deep-merging untrusted objects.'],
  },
  'OWASP SQL Injection Prevention Cheat Sheet': {
    slug: 'SQL_Injection_Prevention_Cheat_Sheet',
    focus: 'Parameterized execution, allow-listed structural tokens, and safe query construction.',
    common_actions: ['Use prepared statements or ORM-safe bindings.', 'Allow-list dynamic query structure separately from values.'],
    avoid: ['Building SQL by concatenating user input.'],
  },
  'OWASP Secrets Management Cheat Sheet': {
    slug: 'Secrets_Management_Cheat_Sheet',
    focus: 'Secret storage, rotation, retrieval, and avoiding credentials in source or logs.',
    common_actions: ['Move secrets to a manager or environment injection.', 'Rotate exposed secrets quickly.'],
    avoid: ['Hardcoding long-lived credentials in code or config.'],
  },
  'OWASP Server Side Request Forgery Prevention Cheat Sheet': {
    slug: 'Server_Side_Request_Forgery_Prevention_Cheat_Sheet',
    focus: 'Outbound request validation, destination allow-lists, and internal network protection.',
    common_actions: ['Allow-list reachable destinations.', 'Constrain protocols, redirects, and internal address access.'],
    avoid: ['Fetching arbitrary attacker-supplied URLs from server-side code.'],
  },
  'OWASP Server Side Template Injection Prevention guidance': {
    slug: 'Server_Side_Template_Injection_Prevention_Cheat_Sheet',
    source_slug: 'Cross_Site_Scripting_Prevention_Cheat_Sheet',
    focus: 'Trusted template boundaries, untrusted expressions, and safe rendering patterns.',
    common_actions: ['Treat templates as trusted assets only.', 'Keep user data as data, not executable template syntax.'],
    avoid: ['Evaluating attacker-controlled template expressions.'],
    source_note: 'Nearest official OWASP cheat sheet source is the Cross Site Scripting Prevention Cheat Sheet template-injection guidance.',
  },
  'OWASP Unvalidated Redirects and Forwards Cheat Sheet': {
    slug: 'Unvalidated_Redirects_and_Forwards_Cheat_Sheet',
    focus: 'Redirect destination allow-lists and server-side route resolution.',
    common_actions: ['Allow-list destinations or route names.', 'Resolve redirects on the server instead of trusting raw URLs.'],
    avoid: ['Redirecting directly to user-supplied URLs.'],
  },
  'OWASP XML External Entity Prevention Cheat Sheet': {
    slug: 'XML_External_Entity_Prevention_Cheat_Sheet',
    focus: 'Safe XML parser configuration, entity resolution control, and DTD hardening.',
    common_actions: ['Disable external entities and DTD processing.', 'Use hardened parser defaults for untrusted XML.'],
    avoid: ['Parsing attacker-controlled XML with entity resolution enabled.'],
  },
};

const issuePackPath = path.join(repoRoot, 'docs', 'data', 'issues', 'owlvex-issue-pack.v1.json');
const remediationPackPath = path.join(repoRoot, 'docs', 'data', 'remediation', 'owlvex-remediation-pack.v1.json');
const targetPath = path.join(repoRoot, 'docs', 'data', 'cheatsheets', 'owlvex.owasp-cheatsheets.2026.1.json');

const readJson = async filePath => JSON.parse(await readFile(filePath, 'utf8'));

function collectIssueRefs(issuePack) {
  const map = new Map();
  for (const issue of issuePack.issues ?? []) {
    for (const ref of issue.remediation?.cheat_sheet_refs ?? []) {
      const current = map.get(ref) ?? { issue_ids: [] };
      current.issue_ids.push(issue.id);
      map.set(ref, current);
    }
  }
  return map;
}

function collectRemediationRefs(remediationPack) {
  const map = new Map();
  for (const entry of remediationPack.entries ?? []) {
    for (const ref of entry.references ?? []) {
      if (ref.kind !== 'cheat-sheet' || !ref.label) continue;
      const current = map.get(ref.label) ?? { remediation_entry_ids: [] };
      current.remediation_entry_ids.push(entry.id);
      map.set(ref.label, current);
    }
  }
  return map;
}

async function main() {
  const issuePack = await readJson(issuePackPath);
  const remediationPack = await readJson(remediationPackPath);
  const issueRefs = collectIssueRefs(issuePack);
  const remediationRefs = collectRemediationRefs(remediationPack);

  const entries = Object.entries(cheatSheetMeta).map(([label, meta]) => ({
    id: `owlvex.cheatsheet.${meta.slug.toLowerCase().replace(/[^a-z0-9]+/g, '.')}`,
    label,
    framework: 'OWASP',
    series: 'OWASP Cheat Sheet Series',
    url: `https://cheatsheetseries.owasp.org/cheatsheets/${meta.source_slug ?? meta.slug}.html`,
    raw_blob_ref: `docs/data/framework-sources/raw/owasp-cheatsheets/${meta.slug}.html`,
    focus: meta.focus,
    common_actions: meta.common_actions,
    avoid: meta.avoid,
    source_note: meta.source_note ?? null,
    issue_ids: [...new Set(issueRefs.get(label)?.issue_ids ?? [])],
    remediation_entry_ids: [...new Set(remediationRefs.get(label)?.remediation_entry_ids ?? [])],
    provenance: {
      source_type: 'hybrid',
      curation_method: 'manual',
      review_status: 'reviewed',
      reviewed_by: 'owlvex-security',
      reviewed_at: '2026-04-15T14:20:00Z',
      sources: [
        {
          label,
          kind: 'cheat-sheet',
          publisher: 'OWASP',
          url: `https://cheatsheetseries.owasp.org/cheatsheets/${meta.source_slug ?? meta.slug}.html`,
        },
      ],
    },
  })).sort((a, b) => a.label.localeCompare(b.label));

  const pack = {
    schema_version: 'owlvex.cheatsheet-pack.v1',
    pack_id: 'owlvex.owasp-cheatsheets.2026.1',
    title: 'Owlvex Curated OWASP Cheat Sheet Pack 2026.1',
    description: 'Curated OWASP Cheat Sheet Series metadata, source blob references, and issue/remediation links for grounded AI remediation guidance.',
    generated_at: '2026-04-15T14:20:00Z',
    entries,
  };

  await mkdir(path.dirname(targetPath), { recursive: true });
  await writeFile(targetPath, `${JSON.stringify(pack, null, 2)}\n`, 'utf8');
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
