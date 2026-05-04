import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const extensionRoot = process.cwd();
const manifest = JSON.parse(fs.readFileSync(path.join(extensionRoot, 'package.json'), 'utf8'));

const expectedPackages = [
  {
    label: 'prod',
    file: path.join(extensionRoot, 'dist', 'owlvex-prod.vsix'),
    name: 'owlvex',
    displayName: 'Owlvex',
    publisher: 'owlvex',
    profileName: 'prod',
  },
  {
    label: 'dev',
    file: path.join(extensionRoot, 'dist', 'owlvex-dev.vsix'),
    name: 'owlvex-dev',
    displayName: 'Owlvex Dev',
    publisher: 'owlvex',
    profileName: 'dev',
  },
];

function readVsixFile(vsixPath, innerPath) {
  const result = spawnSync('tar', ['-xOf', vsixPath, innerPath], {
    cwd: extensionRoot,
    encoding: 'utf8',
    shell: process.platform === 'win32',
  });

  if (result.status !== 0) {
    throw new Error(`Could not read ${innerPath} from ${path.basename(vsixPath)}: ${result.stderr || result.stdout}`);
  }

  return result.stdout;
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`${message}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

for (const expected of expectedPackages) {
  if (!fs.existsSync(expected.file)) {
    throw new Error(`Missing ${expected.label} package at ${expected.file}`);
  }

  const packageJson = JSON.parse(readVsixFile(expected.file, 'extension/package.json'));
  assertEqual(packageJson.name, expected.name, `${expected.label} package name`);
  assertEqual(packageJson.displayName, expected.displayName, `${expected.label} display name`);
  assertEqual(packageJson.publisher, expected.publisher, `${expected.label} publisher`);
  assertEqual(packageJson.version, manifest.version, `${expected.label} version`);

  const readme = readVsixFile(expected.file, 'extension/README.md');
  if (readme.includes('{{PACKAGE_VERSION}}')) {
    throw new Error(`${expected.label} README still contains an unreplaced version placeholder`);
  }
  if (!readme.includes(`\`${manifest.version}\``)) {
    throw new Error(`${expected.label} README does not contain the packaged version ${manifest.version}`);
  }

  const profileSource = readVsixFile(expected.file, 'extension/out/profile.js');
  if (!profileSource.includes(`profileName: "${expected.profileName}"`) && !profileSource.includes(`"profileName": "${expected.profileName}"`)) {
    throw new Error(`${expected.label} package profile source does not contain profileName ${expected.profileName}`);
  }

  console.log(`Verified ${expected.label} package: ${packageJson.name} ${packageJson.version}`);
}
