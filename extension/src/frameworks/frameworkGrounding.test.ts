import {
    buildGroundedFrameworkPromptContext,
    configureFrameworkPackRuntime,
    getGroundedFrameworkLabels,
} from './frameworkGrounding';

describe('frameworkGrounding', () => {
    afterEach(() => {
        configureFrameworkPackRuntime(undefined);
    });

    it('uses runtime framework packs before bundled fallback data', () => {
        configureFrameworkPackRuntime({
            frameworks: [{
                code: 'OWASP',
                name: 'Azure OWASP Pack',
                version: '2025',
                description: 'Azure-served framework profile.',
            }],
            profiles: [{
                id: 'runtime-owasp',
                framework_code: 'OWASP',
                title: 'Azure OWASP Prompt Profile',
                purpose: 'Prove runtime pack grounding is active.',
                prompt_guidance: ['Use the Azure-served guidance first.'],
                report_focus: ['pack-backed evidence'],
                allowed_mapping_fields: ['owasp', 'cwe'],
                ai_usage_rules: ['Do not invent mappings.'],
            }],
        });

        expect(getGroundedFrameworkLabels(['OWASP'])).toEqual(['Azure OWASP Pack']);

        const promptContext = buildGroundedFrameworkPromptContext(['OWASP']);
        expect(promptContext).toContain('Azure OWASP Pack');
        expect(promptContext).toContain('Prove runtime pack grounding is active.');
        expect(promptContext).toContain('Use the Azure-served guidance first.');
    });

    it('falls back to bundled framework data when no runtime pack is active', () => {
        expect(getGroundedFrameworkLabels(['CWE'])).toEqual(['Common Weakness Enumeration']);
    });
});
