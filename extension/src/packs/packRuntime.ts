export type RulePackRuntimeMode = 'fresh' | 'cached' | 'bundled';

export interface RulePackRuntimeContext {
    mode: RulePackRuntimeMode;
    packIds: string[];
    fetchedAt?: string;
    manifestFreshness?: 'fresh' | 'stale';
}

export function getRulePackModeLabel(context?: RulePackRuntimeContext): string {
    if (context?.mode === 'cached' && context.manifestFreshness === 'stale') {
        return 'Cached Packs (Stale Manifest)';
    }

    switch (context?.mode) {
        case 'fresh':
            return 'Fresh Packs';
        case 'cached':
            return 'Cached Packs';
        case 'bundled':
        default:
            return 'Bundled Fallback';
    }
}

export function describeRulePackRuntime(context?: RulePackRuntimeContext): string {
    const label = getRulePackModeLabel(context);
    const packSummary = context?.packIds?.length ? context.packIds.join(', ') : 'no verified packs loaded';
    const fetched = context?.fetchedAt ? ` | fetched ${context.fetchedAt}` : '';
    return `${label} | ${packSummary}${fetched}`;
}
