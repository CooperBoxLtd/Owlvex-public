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
const profileSourcePath = path.join(extensionRoot, "src", "profile.ts");

if (!fs.existsSync(profilePath)) {
  console.error(`Unknown profile '${profileName}'. Expected ${profilePath}`);
  process.exit(1);
}

const originalManifestText = fs.readFileSync(packageJsonPath, "utf8");
const originalProfileSource = fs.readFileSync(profileSourcePath, "utf8");
const manifest = JSON.parse(originalManifestText);
const profile = JSON.parse(fs.readFileSync(profilePath, "utf8"));
const prodProfile = JSON.parse(fs.readFileSync(path.join(extensionRoot, "profiles", "prod.json"), "utf8"));

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

const originalProperties = manifest.contributes?.configuration?.properties ?? {};
const rewrittenProperties = {};
for (const [key, value] of Object.entries(originalProperties)) {
  const nextKey = key.replace(/^owlvex\./, `${profile.configSection}.`);
  rewrittenProperties[nextKey] = value;
}
manifest.contributes.configuration.properties = rewrittenProperties;
if (manifest.contributes.configuration.properties[`${profile.configSection}.apiUrl`]) {
  manifest.contributes.configuration.properties[`${profile.configSection}.apiUrl`].default = profile.apiUrl;
}

const commandIdMap = {
  "owlvex.scanFile": `${profile.commandPrefix}.scanFile`,
  "owlvex.scanSelectedFiles": `${profile.commandPrefix}.scanSelectedFiles`,
  "owlvex.scanOpenEditors": `${profile.commandPrefix}.scanOpenEditors`,
  "owlvex.scanWorkspace": `${profile.commandPrefix}.scanWorkspace`,
  "owlvex.scanWorkspaceReport": `${profile.commandPrefix}.scanWorkspaceReport`,
  "owlvex.selectFrameworks": `${profile.commandPrefix}.selectFrameworks`,
  "owlvex.openPromptEditor": `${profile.commandPrefix}.openPromptEditor`,
  "owlvex.switchModel": `${profile.commandPrefix}.switchModel`,
  "owlvex.setupAI": `${profile.commandPrefix}.setupAI`,
  "owlvex.configureBackend": `${profile.commandPrefix}.configureBackend`,
  "owlvex.removeAIConnection": `${profile.commandPrefix}.removeAIConnection`,
  "owlvex.openProjectContext": `${profile.commandPrefix}.openProjectContext`,
  "owlvex.testAIConnection": `${profile.commandPrefix}.testAIConnection`,
  "owlvex.testTrialSetup": `${profile.commandPrefix}.testTrialSetup`,
  "owlvex.enterLicence": `${profile.commandPrefix}.enterLicence`,
  "owlvex.removeLicence": `${profile.commandPrefix}.removeLicence`,
  "owlvex.registerAccess": `${profile.commandPrefix}.registerAccess`,
  "owlvex.compareScans": `${profile.commandPrefix}.compareScans`,
  "owlvex.reviewRiskCalibration": `${profile.commandPrefix}.reviewRiskCalibration`,
  "owlvex.discussFinding": `${profile.commandPrefix}.discussFinding`,
  "owlvex.generateFixPreview": `${profile.commandPrefix}.generateFixPreview`,
  "owlvex.applyFixPreview": `${profile.commandPrefix}.applyFixPreview`,
};

manifest.contributes.commands = manifest.contributes.commands.map((command) => ({
  ...command,
  command: commandIdMap[command.command] ?? command.command,
  title: command.title.replace(/^Owlvex/, profile.displayName),
}));
if (manifest.contributes.menus) {
  for (const [menuId, entries] of Object.entries(manifest.contributes.menus)) {
    manifest.contributes.menus[menuId] = entries.map((entry) => ({
      ...entry,
      command: commandIdMap[entry.command] ?? entry.command,
    }));
  }
}

if (manifest.contributes.viewsContainers?.activitybar?.[0]) {
  manifest.contributes.viewsContainers.activitybar[0].id = profile.viewContainerId;
  manifest.contributes.viewsContainers.activitybar[0].title = profile.displayName;
  manifest.contributes.viewsContainers.activitybar[0].icon = profile.activityBarIcon;
}

const existingViews = manifest.contributes.views?.owlvex ?? [];
delete manifest.contributes.views.owlvex;
manifest.contributes.views[profile.viewContainerId] = existingViews.map((view) => ({
  ...view,
  id: view.id === "owlvex.findings" ? profile.findingsViewId : profile.chatViewId,
}));

const generatedProfileSource = `export const PROFILE = ${JSON.stringify({
  profileName,
  extensionId: `${profile.publisher}.${profile.name}`,
  configSection: profile.configSection,
  displayLabel: profile.displayName,
  statusBarLabel: profile.statusBarLabel,
  activityBarIcon: profile.activityBarIcon,
  defaultApiUrl: profile.apiUrl,
  storagePrefix: profile.storagePrefix,
  secretPrefix: profile.secretPrefix,
  diagnosticCollection: profile.diagnosticCollection,
  viewContainerId: profile.viewContainerId,
  findingsViewId: profile.findingsViewId,
  chatViewId: profile.chatViewId,
  comparisonPanelId: profile.comparisonPanelId,
  commands: {
    scanFile: `${profile.commandPrefix}.scanFile`,
    scanSelectedFiles: `${profile.commandPrefix}.scanSelectedFiles`,
    scanOpenEditors: `${profile.commandPrefix}.scanOpenEditors`,
    scanWorkspace: `${profile.commandPrefix}.scanWorkspace`,
    scanWorkspaceReport: `${profile.commandPrefix}.scanWorkspaceReport`,
    selectFrameworks: `${profile.commandPrefix}.selectFrameworks`,
    openPromptEditor: `${profile.commandPrefix}.openPromptEditor`,
    switchModel: `${profile.commandPrefix}.switchModel`,
    setupAI: `${profile.commandPrefix}.setupAI`,
    configureBackend: `${profile.commandPrefix}.configureBackend`,
    removeAIConnection: `${profile.commandPrefix}.removeAIConnection`,
    openProjectContext: `${profile.commandPrefix}.openProjectContext`,
    testAI: `${profile.commandPrefix}.testAIConnection`,
    testTrialSetup: `${profile.commandPrefix}.testTrialSetup`,
    enterLicence: `${profile.commandPrefix}.enterLicence`,
    removeLicence: `${profile.commandPrefix}.removeLicence`,
    registerAccess: `${profile.commandPrefix}.registerAccess`,
    compareScans: `${profile.commandPrefix}.compareScans`,
    reviewRiskCalibration: `${profile.commandPrefix}.reviewRiskCalibration`,
    discussFinding: `${profile.commandPrefix}.discussFinding`,
    generateFixPreview: `${profile.commandPrefix}.generateFixPreview`,
    applyFixPreview: `${profile.commandPrefix}.applyFixPreview`,
    revealLine: `${profile.commandPrefix}.revealLine`,
    chatFocus: `${profile.chatViewId}.focus`
  }
}, null, 4)} as const;\n`;

let exitCode = 0;
try {
  fs.writeFileSync(packageJsonPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  fs.writeFileSync(profileSourcePath, generatedProfileSource, "utf8");

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
}

if (exitCode !== 0) {
  process.exit(exitCode);
}
