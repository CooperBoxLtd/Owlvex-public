import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import packageProfileLib from "./package-profile-lib.cjs";

const { buildGeneratedProfileSource, rewriteManifestForProfile } = packageProfileLib;

const profileName = process.argv[2];

if (!profileName) {
  console.error("Usage: node scripts/package-profile.mjs <dev|prod>");
  process.exit(1);
}

const extensionRoot = process.cwd();
const packageJsonPath = path.join(extensionRoot, "package.json");
const profilePath = path.join(extensionRoot, "profiles", `${profileName}.json`);
const profileSourcePath = path.join(extensionRoot, "src", "profile.ts");
const readmePath = path.join(extensionRoot, "README.md");
const profileReadmePath = path.join(extensionRoot, "profiles", `${profileName}.README.md`);

if (!fs.existsSync(profilePath)) {
  console.error(`Unknown profile '${profileName}'. Expected ${profilePath}`);
  process.exit(1);
}

const originalManifestText = fs.readFileSync(packageJsonPath, "utf8");
const originalProfileSource = fs.readFileSync(profileSourcePath, "utf8");
const hadOriginalReadme = fs.existsSync(readmePath);
const originalReadmeText = hadOriginalReadme ? fs.readFileSync(readmePath, "utf8") : "";
let manifest = JSON.parse(originalManifestText);
const profile = JSON.parse(fs.readFileSync(profilePath, "utf8"));
const prodProfile = JSON.parse(fs.readFileSync(path.join(extensionRoot, "profiles", "prod.json"), "utf8"));
const profileReadmeText = fs.existsSync(profileReadmePath) ? fs.readFileSync(profileReadmePath, "utf8") : originalReadmeText;

if (manifest.name !== prodProfile.name || !originalProfileSource.includes(`"profileName": "prod"`)) {
  console.error("Packaging must start from the checked-in prod baseline. Restore extension/package.json and src/profile.ts, then retry.");
  process.exit(1);
}

const packagePath = path.join(extensionRoot, profile.packagePath);
fs.mkdirSync(path.dirname(packagePath), { recursive: true });

manifest.name = profile.name;
manifest.displayName = profile.displayName;
manifest.description = profile.description;
manifest.publisher = profile.publisher;
manifest.contributes.configuration.title = profile.displayName;
manifest = rewriteManifestForProfile(manifest, profile);
const generatedProfileSource = buildGeneratedProfileSource(profileName, profile);

let exitCode = 0;
try {
  fs.writeFileSync(packageJsonPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  fs.writeFileSync(profileSourcePath, generatedProfileSource, "utf8");
  fs.writeFileSync(readmePath, profileReadmeText, "utf8");

  const compile = spawnSync("npm", ["run", "compile"], {
    cwd: extensionRoot,
    stdio: "inherit",
    shell: true,
  });
  if (compile.status !== 0) {
    exitCode = compile.status ?? 1;
    throw new Error(`Compile failed for profile '${profileName}'`);
  }

  const pkg = spawnSync("npx", ["@vscode/vsce", "package", "--out", packagePath], {
    cwd: extensionRoot,
    stdio: "inherit",
    shell: true,
  });
  if (pkg.status !== 0) {
    exitCode = pkg.status ?? 1;
    throw new Error(`Packaging failed for profile '${profileName}'`);
  }

  console.log(`Built ${profileName} package at ${packagePath}`);
} catch (error) {
  if (!exitCode) {
    exitCode = 1;
  }
  console.error(error instanceof Error ? error.message : String(error));
} finally {
  fs.writeFileSync(packageJsonPath, originalManifestText, "utf8");
  fs.writeFileSync(profileSourcePath, originalProfileSource, "utf8");
  if (hadOriginalReadme) {
    fs.writeFileSync(readmePath, originalReadmeText, "utf8");
  } else if (fs.existsSync(readmePath)) {
    fs.unlinkSync(readmePath);
  }
}

if (exitCode !== 0) {
  process.exit(exitCode);
}
