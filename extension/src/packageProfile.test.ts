import fs from 'node:fs';
import path from 'node:path';

const extensionRoot = path.resolve(__dirname, '..');

function loadPackagingHelpers() {
    const modulePath = path.join(extensionRoot, 'scripts', 'package-profile-lib.cjs');
    return require(modulePath);
}

describe('package profile helpers', () => {
    it('rewrites commands, settings, and views for the dev profile', async () => {
        const { rewriteManifestForProfile } = loadPackagingHelpers();
        const manifest = JSON.parse(fs.readFileSync(path.join(extensionRoot, 'package.json'), 'utf8'));
        const devProfile = JSON.parse(fs.readFileSync(path.join(extensionRoot, 'profiles', 'dev.json'), 'utf8'));

        const rewritten = rewriteManifestForProfile(manifest, devProfile);

        const commandIds = rewritten.contributes.commands.map((entry: { command: string }) => entry.command);
        expect(commandIds).toContain('owlvexDev.configureProviderThrottling');
        expect(commandIds).not.toContain('owlvex.configureProviderThrottling');

        expect(rewritten.contributes.configuration.properties['owlvexDev.providerThrottleOverrides']).toBeDefined();
        expect(rewritten.contributes.configuration.properties['owlvexDev.apiUrl'].default).toBe(devProfile.apiUrl);
        expect(rewritten.contributes.viewsContainers.activitybar[0]).toMatchObject({
            id: devProfile.viewContainerId,
            title: devProfile.displayName,
            icon: devProfile.activityBarIcon,
        });
        expect(rewritten.contributes.views[devProfile.viewContainerId].map((view: { id: string }) => view.id)).toEqual([
            devProfile.findingsViewId,
            devProfile.chatViewId,
        ]);
    });

    it('builds generated profile source with the throttling command and profile-specific ids', async () => {
        const { buildGeneratedProfileSource } = loadPackagingHelpers();
        const devProfile = JSON.parse(fs.readFileSync(path.join(extensionRoot, 'profiles', 'dev.json'), 'utf8'));

        const source = buildGeneratedProfileSource('dev', devProfile);

        expect(source).toContain('configureProviderThrottling');
        expect(source).toContain('"configSection": "owlvexDev"');
        expect(source).toContain('"chatFocus": "owlvexDev.chat.focus"');
        expect(source).toContain('"compareScans": "owlvexDev.compareScans"');
    });
});
