function buildCommandIdMap(profile) {
  return {
    "owlvex.scanFile": `${profile.commandPrefix}.scanFile`,
    "owlvex.scanSelectedFiles": `${profile.commandPrefix}.scanSelectedFiles`,
    "owlvex.scanChangedFiles": `${profile.commandPrefix}.scanChangedFiles`,
    "owlvex.scanOpenEditors": `${profile.commandPrefix}.scanOpenEditors`,
    "owlvex.scanWorkspace": `${profile.commandPrefix}.scanWorkspace`,
    "owlvex.scanWorkspaceReport": `${profile.commandPrefix}.scanWorkspaceReport`,
    "owlvex.selectFrameworks": `${profile.commandPrefix}.selectFrameworks`,
    "owlvex.openPromptEditor": `${profile.commandPrefix}.openPromptEditor`,
    "owlvex.switchModel": `${profile.commandPrefix}.switchModel`,
    "owlvex.configureProviderThrottling": `${profile.commandPrefix}.configureProviderThrottling`,
    "owlvex.setupAI": `${profile.commandPrefix}.setupAI`,
    "owlvex.configureBackend": `${profile.commandPrefix}.configureBackend`,
    "owlvex.removeAIConnection": `${profile.commandPrefix}.removeAIConnection`,
    "owlvex.openProjectContext": `${profile.commandPrefix}.openProjectContext`,
    "owlvex.openTddBox": `${profile.commandPrefix}.openTddBox`,
    "owlvex.openDesignContext": `${profile.commandPrefix}.openDesignContext`,
    "owlvex.openDriftBox": `${profile.commandPrefix}.openDriftBox`,
    "owlvex.testAIConnection": `${profile.commandPrefix}.testAIConnection`,
    "owlvex.testTrialSetup": `${profile.commandPrefix}.testTrialSetup`,
    "owlvex.showOnboarding": `${profile.commandPrefix}.showOnboarding`,
    "owlvex.selectProjectRoot": `${profile.commandPrefix}.selectProjectRoot`,
    "owlvex.enterLicence": `${profile.commandPrefix}.enterLicence`,
    "owlvex.removeLicence": `${profile.commandPrefix}.removeLicence`,
    "owlvex.toggleTelemetry": `${profile.commandPrefix}.toggleTelemetry`,
    "owlvex.registerAccess": `${profile.commandPrefix}.registerAccess`,
    "owlvex.compareScans": `${profile.commandPrefix}.compareScans`,
    "owlvex.compareLatestReports": `${profile.commandPrefix}.compareLatestReports`,
    "owlvex.reviewRiskCalibration": `${profile.commandPrefix}.reviewRiskCalibration`,
    "owlvex.discussFinding": `${profile.commandPrefix}.discussFinding`,
    "owlvex.generateFixPreview": `${profile.commandPrefix}.generateFixPreview`,
    "owlvex.applyFixPreview": `${profile.commandPrefix}.applyFixPreview`,
  };
}

function rewriteManifestForProfile(manifest, profile) {
  const nextManifest = JSON.parse(JSON.stringify(manifest));
  const commandIdMap = buildCommandIdMap(profile);

  nextManifest.name = profile.name;
  nextManifest.displayName = profile.displayName;
  nextManifest.description = profile.description;
  nextManifest.publisher = profile.publisher;
  nextManifest.contributes.configuration.title = profile.displayName;

  const originalProperties = nextManifest.contributes?.configuration?.properties ?? {};
  const rewrittenProperties = {};
  for (const [key, value] of Object.entries(originalProperties)) {
    const nextKey = key.replace(/^owlvex\./, `${profile.configSection}.`);
    rewrittenProperties[nextKey] = value;
  }
  nextManifest.contributes.configuration.properties = rewrittenProperties;
  if (nextManifest.contributes.configuration.properties[`${profile.configSection}.apiUrl`]) {
    nextManifest.contributes.configuration.properties[`${profile.configSection}.apiUrl`].default = profile.apiUrl;
  }

  nextManifest.contributes.commands = nextManifest.contributes.commands.map((command) => ({
    ...command,
    command: commandIdMap[command.command] ?? command.command,
    title: command.title.replace(/^Owlvex/, profile.displayName),
  }));

  if (nextManifest.contributes.menus) {
    for (const [menuId, entries] of Object.entries(nextManifest.contributes.menus)) {
      nextManifest.contributes.menus[menuId] = entries.map((entry) => ({
        ...entry,
        command: commandIdMap[entry.command] ?? entry.command,
      }));
    }
  }

  if (nextManifest.contributes.viewsContainers?.activitybar?.[0]) {
    nextManifest.contributes.viewsContainers.activitybar[0].id = profile.viewContainerId;
    nextManifest.contributes.viewsContainers.activitybar[0].title = profile.displayName;
    nextManifest.contributes.viewsContainers.activitybar[0].icon = profile.activityBarIcon;
  }

  const existingViews = nextManifest.contributes.views?.owlvex ?? [];
  delete nextManifest.contributes.views.owlvex;
  nextManifest.contributes.views[profile.viewContainerId] = existingViews.map((view) => ({
    ...view,
    id: view.id === "owlvex.findings" ? profile.findingsViewId : profile.chatViewId,
  }));

  return nextManifest;
}

function buildGeneratedProfileSource(profileName, profile) {
  return `export const PROFILE = ${JSON.stringify({
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
    owaspTop10Version: profile.owaspTop10Version ?? "2021",
    commands: {
      scanFile: `${profile.commandPrefix}.scanFile`,
      scanSelectedFiles: `${profile.commandPrefix}.scanSelectedFiles`,
      scanChangedFiles: `${profile.commandPrefix}.scanChangedFiles`,
      scanOpenEditors: `${profile.commandPrefix}.scanOpenEditors`,
      scanWorkspace: `${profile.commandPrefix}.scanWorkspace`,
      scanWorkspaceReport: `${profile.commandPrefix}.scanWorkspaceReport`,
      selectFrameworks: `${profile.commandPrefix}.selectFrameworks`,
      openPromptEditor: `${profile.commandPrefix}.openPromptEditor`,
      switchModel: `${profile.commandPrefix}.switchModel`,
      configureProviderThrottling: `${profile.commandPrefix}.configureProviderThrottling`,
      setupAI: `${profile.commandPrefix}.setupAI`,
      configureBackend: `${profile.commandPrefix}.configureBackend`,
      removeAIConnection: `${profile.commandPrefix}.removeAIConnection`,
      openProjectContext: `${profile.commandPrefix}.openProjectContext`,
      openTddBox: `${profile.commandPrefix}.openTddBox`,
      openDesignContext: `${profile.commandPrefix}.openDesignContext`,
      openDriftBox: `${profile.commandPrefix}.openDriftBox`,
      testAI: `${profile.commandPrefix}.testAIConnection`,
      testTrialSetup: `${profile.commandPrefix}.testTrialSetup`,
      showOnboarding: `${profile.commandPrefix}.showOnboarding`,
      selectProjectRoot: `${profile.commandPrefix}.selectProjectRoot`,
      enterLicence: `${profile.commandPrefix}.enterLicence`,
      removeLicence: `${profile.commandPrefix}.removeLicence`,
      toggleTelemetry: `${profile.commandPrefix}.toggleTelemetry`,
      registerAccess: `${profile.commandPrefix}.registerAccess`,
      compareScans: `${profile.commandPrefix}.compareScans`,
      compareLatestReports: `${profile.commandPrefix}.compareLatestReports`,
      reviewRiskCalibration: `${profile.commandPrefix}.reviewRiskCalibration`,
      discussFinding: `${profile.commandPrefix}.discussFinding`,
      generateFixPreview: `${profile.commandPrefix}.generateFixPreview`,
      applyFixPreview: `${profile.commandPrefix}.applyFixPreview`,
      revealLine: `${profile.commandPrefix}.revealLine`,
      chatFocus: `${profile.chatViewId}.focus`
    }
  }, null, 4)} as const;\n`;
}

module.exports = {
  buildCommandIdMap,
  rewriteManifestForProfile,
  buildGeneratedProfileSource,
};
