import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');
const targetRoot = path.join(repoRoot, 'docs', 'data', 'framework-sources');
const rawRoot = path.join(targetRoot, 'raw');

const owaspCheatSheets = [
  { title: 'OWASP Authentication Cheat Sheet', slug: 'Authentication_Cheat_Sheet' },
  { title: 'OWASP Authorization Cheat Sheet', slug: 'Authorization_Cheat_Sheet' },
  { title: 'OWASP Cross Origin Resource Sharing Cheat Sheet', slug: 'Cross_Origin_Resource_Sharing_Cheat_Sheet', sourceSlug: 'REST_Security_Cheat_Sheet', noteSuffix: 'using the OWASP REST Security Cheat Sheet CORS section as the nearest official source.' },
  { title: 'OWASP Cross Site Scripting Prevention Cheat Sheet', slug: 'Cross_Site_Scripting_Prevention_Cheat_Sheet' },
  { title: 'OWASP Cross-Site Request Forgery Prevention Cheat Sheet', slug: 'Cross-Site_Request_Forgery_Prevention_Cheat_Sheet' },
  { title: 'OWASP Cryptographic Storage Cheat Sheet', slug: 'Cryptographic_Storage_Cheat_Sheet' },
  { title: 'OWASP Deserialization Cheat Sheet', slug: 'Deserialization_Cheat_Sheet' },
  { title: 'OWASP Error Handling Cheat Sheet', slug: 'Error_Handling_Cheat_Sheet' },
  { title: 'OWASP File Upload Cheat Sheet', slug: 'File_Upload_Cheat_Sheet' },
  { title: 'OWASP Input Validation Cheat Sheet', slug: 'Input_Validation_Cheat_Sheet' },
  { title: 'OWASP JSON Web Token Cheat Sheet for Java', slug: 'JSON_Web_Token_for_Java_Cheat_Sheet' },
  { title: 'OWASP LDAP Injection Prevention Cheat Sheet', slug: 'LDAP_Injection_Prevention_Cheat_Sheet' },
  { title: 'OWASP Logging Cheat Sheet', slug: 'Logging_Cheat_Sheet' },
  { title: 'OWASP Mass Assignment Cheat Sheet', slug: 'Mass_Assignment_Cheat_Sheet' },
  { title: 'OWASP NoSQL Security Cheat Sheet', slug: 'NoSQL_Security_Cheat_Sheet' },
  { title: 'OWASP OS Command Injection Defense Cheat Sheet', slug: 'OS_Command_Injection_Defense_Cheat_Sheet' },
  { title: 'OWASP Path Traversal Cheat Sheet', slug: 'Path_Traversal_Cheat_Sheet', sourceSlug: 'Symfony_Cheat_Sheet', noteSuffix: 'using the OWASP Symfony Cheat Sheet path traversal section as the nearest official source.' },
  { title: 'OWASP Prototype Pollution Prevention Cheat Sheet', slug: 'Prototype_Pollution_Prevention_Cheat_Sheet' },
  { title: 'OWASP SQL Injection Prevention Cheat Sheet', slug: 'SQL_Injection_Prevention_Cheat_Sheet' },
  { title: 'OWASP Secrets Management Cheat Sheet', slug: 'Secrets_Management_Cheat_Sheet' },
  { title: 'OWASP Server Side Request Forgery Prevention Cheat Sheet', slug: 'Server_Side_Request_Forgery_Prevention_Cheat_Sheet' },
  { title: 'OWASP Server Side Template Injection Prevention guidance', slug: 'Server_Side_Template_Injection_Prevention_Cheat_Sheet', sourceSlug: 'Cross_Site_Scripting_Prevention_Cheat_Sheet', noteSuffix: 'using the OWASP Cross Site Scripting Prevention Cheat Sheet template-injection guidance as the nearest official source.' },
  { title: 'OWASP Unvalidated Redirects and Forwards Cheat Sheet', slug: 'Unvalidated_Redirects_and_Forwards_Cheat_Sheet' },
  { title: 'OWASP XML External Entity Prevention Cheat Sheet', slug: 'XML_External_Entity_Prevention_Cheat_Sheet' },
].map(({ title, slug, sourceSlug, noteSuffix }) => ({
  id: `owasp-cheatsheet-${slug.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`,
  framework: 'OWASP Cheat Sheet Series',
  title,
  url: `https://cheatsheetseries.owasp.org/cheatsheets/${sourceSlug ?? slug}.html`,
  target: path.join(rawRoot, 'owasp-cheatsheets', `${slug}.html`),
  format: 'html',
  note: noteSuffix
    ? `Official OWASP Cheat Sheet Series source for ${title}, ${noteSuffix}`
    : `Official OWASP Cheat Sheet Series page for ${title}.`,
}));

const downloadableSources = [
  {
    id: 'cwe-xml-latest',
    framework: 'CWE',
    title: 'CWE XML latest',
    url: 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip',
    target: path.join(rawRoot, 'cwe', 'cwec_latest.xml.zip'),
    format: 'zip',
    note: 'Official MITRE CWE XML export.',
  },
  {
    id: 'cwe-csv-top-level',
    framework: 'CWE',
    title: 'CWE CSV export',
    url: 'https://cwe.mitre.org/data/csv/1000.csv.zip',
    target: path.join(rawRoot, 'cwe', '1000.csv.zip'),
    format: 'zip',
    note: 'Official MITRE CWE CSV export.',
  },
  {
    id: 'mitre-attack-index',
    framework: 'MITRE ATT&CK',
    title: 'MITRE ATT&CK index',
    url: 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json',
    target: path.join(rawRoot, 'attack', 'index.json'),
    format: 'json',
    note: 'Official ATT&CK dataset index from the MITRE ATT&CK STIX repository.',
  },
  {
    id: 'mitre-attack-enterprise',
    framework: 'MITRE ATT&CK',
    title: 'MITRE ATT&CK enterprise dataset',
    url: 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json',
    target: path.join(rawRoot, 'attack', 'enterprise-attack.json'),
    format: 'json',
    note: 'Large official ATT&CK enterprise STIX bundle.',
  },
  {
    id: 'owasp-top10-2021',
    framework: 'OWASP',
    title: 'OWASP Top 10 2021',
    url: 'https://owasp.org/Top10/2021/',
    target: path.join(rawRoot, 'owasp', 'top10-2021.html'),
    format: 'html',
    note: 'Official OWASP Top 10 2021 project page.',
  },
  {
    id: 'owasp-api-top10-2023',
    framework: 'OWASP API Security',
    title: 'OWASP API Security Top 10 2023',
    url: 'https://owasp.org/API-Security/editions/2023/en/0x00-header/',
    target: path.join(rawRoot, 'owasp', 'api-security-top10-2023.html'),
    format: 'html',
    note: 'Official OWASP API Security Top 10 2023 project page.',
  },
  {
    id: 'nist-sp800-53-r5',
    framework: 'NIST',
    title: 'NIST SP 800-53 Rev. 5 derived OSCAL spreadsheet',
    url: 'https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/NIST_SP-800-53_rev5-derived-OSCAL.xlsx',
    target: path.join(rawRoot, 'nist', 'NIST_SP-800-53_rev5-derived-OSCAL.xlsx'),
    format: 'xlsx',
    note: 'Official NIST SP 800-53 Rev. 5 derivative spreadsheet.',
  },
  ...owaspCheatSheets,
];

const sourceOnlyReferences = [
  {
    id: 'hipaa-security-rule',
    framework: 'HIPAA',
    title: 'HIPAA Security Rule',
    url: 'https://www.hhs.gov/hipaa/for-professionals/security/index.html',
    status: 'source-only',
    note: 'Official HHS source. Automated download was blocked from this environment; keep as a reference until a compliant fetch/import path is added.',
  },
  {
    id: 'pci-dss-standard',
    framework: 'PCI DSS',
    title: 'PCI DSS standards page',
    url: 'https://www.pcisecuritystandards.org/standards/pci-dss/',
    status: 'source-only',
    note: 'Keep as a source reference. Mirror only curated derivatives unless licensing review says otherwise.',
  },
];

async function downloadSource(source) {
  await mkdir(path.dirname(source.target), { recursive: true });
  const response = await fetch(source.url, {
    headers: {
      'user-agent': 'Owlvex Framework Downloader/1.0',
    },
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }

  const arrayBuffer = await response.arrayBuffer();
  const buffer = Buffer.from(arrayBuffer);
  await writeFile(source.target, buffer);

  return {
    ...source,
    status: 'downloaded',
    bytes: buffer.byteLength,
    downloaded_at: new Date().toISOString(),
    relative_target: path.relative(repoRoot, source.target).replace(/\\/g, '/'),
  };
}

async function main() {
  const results = [];

  for (const source of downloadableSources) {
    try {
      results.push(await downloadSource(source));
      console.log(`downloaded ${source.id}`);
    } catch (error) {
      results.push({
        ...source,
        status: 'failed',
        error: error instanceof Error ? error.message : String(error),
      });
      console.warn(`failed ${source.id}`);
    }
  }

  results.push(...sourceOnlyReferences);

  await mkdir(targetRoot, { recursive: true });
  await writeFile(
    path.join(targetRoot, 'download-status.json'),
    JSON.stringify({
      generated_at: new Date().toISOString(),
      items: results,
    }, null, 2),
    'utf8',
  );
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
