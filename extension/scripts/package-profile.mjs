import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const profileName = process.argv[2];

if (!profileName) {
  console.error("Usage: node scripts/package-profile.mjs <dev|prod>");
  process.exit(1);
}

const extensionRoot = process.cwd();
const packageJsonPath = path.join(extensionRoot, "package.json");
const profilePath = path.join(extensionRoot, "profiles", `${profileName}.json`);

if (!fs.existsSync(profilePath)) {
  console.error(`Unknown profile '${profileName}'. Expected ${profilePath}`);
  process.exit(1);
}

const originalManifestText = fs.readFileSync(packageJsonPath, "utf8");
const manifest = JSON.parse(originalManifestText);
const profile = JSON.parse(fs.readFileSync(profilePath, "utf8"));

const packagePath = path.join(extensionRoot, profile.packagePath);
fs.mkdirSync(path.dirname(packagePath), { recursive: true });

manifest.name = profile.name;
manifest.displayName = profile.displayName;
manifest.description = profile.description;
manifest.publisher = profile.publisher;

if (manifest.contributes?.configuration?.properties?.["owlvex.apiUrl"]) {
  manifest.contributes.configuration.properties["owlvex.apiUrl"].default = profile.apiUrl;
}

try {
  fs.writeFileSync(packageJsonPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

  const compile = spawnSync("npm", ["run", "compile"], {
    cwd: extensionRoot,
    stdio: "inherit",
    shell: true,
  });
  if (compile.status !== 0) {
    process.exit(compile.status ?? 1);
  }

  const pkg = spawnSync("npx", ["@vscode/vsce", "package", "--out", packagePath], {
    cwd: extensionRoot,
    stdio: "inherit",
    shell: true,
  });
  if (pkg.status !== 0) {
    process.exit(pkg.status ?? 1);
  }

  console.log(`Built ${profileName} package at ${packagePath}`);
} finally {
  fs.writeFileSync(packageJsonPath, originalManifestText, "utf8");
}
