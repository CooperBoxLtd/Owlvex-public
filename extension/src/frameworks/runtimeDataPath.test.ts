import { resolveRuntimeDataPath } from './runtimeDataPath';

jest.mock('node:fs', () => ({
    existsSync: jest.fn(),
}));

describe('resolveRuntimeDataPath', () => {
    const fs = jest.requireMock('node:fs') as { existsSync: jest.Mock };
    const normalizeTestPath = (value: string) => value.replace(/\\/g, '/');

    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('prefers packaged extension data assets when available', () => {
        fs.existsSync.mockImplementation((candidate: string) => normalizeTestPath(candidate).includes('/data/frameworks/'));

        const resolved = resolveRuntimeDataPath(
            'c:\\Users\\CristianBogdan\\.vscode\\extensions\\owlvex\\out\\frameworks',
            'frameworks',
            'owlvex.framework-pack.2026.1.json',
        );

        expect(normalizeTestPath(resolved)).toContain('/data/frameworks/owlvex.framework-pack.2026.1.json');
        expect(normalizeTestPath(resolved)).not.toContain('/docs/data/frameworks/');
    });

    it('returns the packaged data candidate when neither path exists', () => {
        fs.existsSync.mockReturnValue(false);

        const resolved = resolveRuntimeDataPath(
            'd:\\Dev\\repos\\CodeScanner\\extension\\out\\frameworks',
            'frameworks',
            'owlvex.framework-pack.2026.1.json',
        );

        expect(normalizeTestPath(resolved)).toContain('/data/frameworks/owlvex.framework-pack.2026.1.json');
        expect(normalizeTestPath(resolved)).not.toContain('/docs/data/frameworks/');
    });
});
