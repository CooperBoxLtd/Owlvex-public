import * as vscode from 'vscode';
import { PROFILE } from '../profile';

const SECRET_KEY = `${PROFILE.secretPrefix}.licenceKey`;

export interface LicenceInfo {
    valid: boolean;
    licenceId: string;
    teamName: string;
    plan: string;
    seats: number;
    seatsUsed: number;
    features: {
        frameworks: string[];
        scansPerMonth: number | null;
        promptEditor: boolean;
        comparison: boolean;
        teamPrompts: boolean;
        ciCd: boolean;
        pdfReports: boolean;
        customRules: boolean;
        sso: boolean;
        industryPacks: string[];
    };
    usage: {
        scansThisMonth: number;
        scansRemaining: number | null;
        monthlyLimitReached: boolean;
    };
    expiresAt: string | null;
}

function titleCasePlan(plan: string | null | undefined): string {
    if (!plan) {
        return 'Unknown';
    }

    return plan.charAt(0).toUpperCase() + plan.slice(1);
}

export function getDaysUntilExpiry(expiresAt: string | null | undefined, now = new Date()): number | null {
    if (!expiresAt) {
        return null;
    }

    const expiry = new Date(expiresAt);
    if (Number.isNaN(expiry.getTime())) {
        return null;
    }

    const diffMs = expiry.getTime() - now.getTime();
    return Math.max(0, Math.ceil(diffMs / (24 * 60 * 60 * 1000)));
}

export function buildLicenceStatusSummary(info: LicenceInfo | null | undefined, now = new Date()): string {
    if (!info) {
        return 'Licence: not connected';
    }

    const parts = [`Licence: ${titleCasePlan(info.plan)}`];
    if (info.teamName) {
        parts.push(info.teamName);
    }

    if (info.plan === 'trial') {
        const daysLeft = getDaysUntilExpiry(info.expiresAt, now);
        if (daysLeft !== null) {
            parts.push(`${daysLeft} day${daysLeft === 1 ? '' : 's'} left`);
        }
    } else if (info.expiresAt) {
        parts.push(`expires ${info.expiresAt.slice(0, 10)}`);
    }

    if (typeof info.features?.scansPerMonth === 'number') {
        const scansThisMonth = info.usage?.scansThisMonth ?? 0;
        parts.push(`${scansThisMonth}/${info.features.scansPerMonth} scans this month`);
    }

    return parts.join(' · ');
}

export function buildLicenceBadgeLabel(info: LicenceInfo | null | undefined, now = new Date()): string | undefined {
    if (!info) {
        return undefined;
    }

    if (info.plan === 'trial') {
        const daysLeft = getDaysUntilExpiry(info.expiresAt, now);
        if (daysLeft !== null) {
            return `Trial · ${daysLeft}d left`;
        }
        return 'Trial';
    }

    return titleCasePlan(info.plan);
}

export function isTrialPlan(info: LicenceInfo | null | undefined): boolean {
    return info?.plan === 'trial';
}

export function isTrialEndingSoon(
    info: LicenceInfo | null | undefined,
    thresholdDays = 2,
    now = new Date(),
): boolean {
    if (!isTrialPlan(info)) {
        return false;
    }

    const daysLeft = getDaysUntilExpiry(info?.expiresAt, now);
    return daysLeft !== null && daysLeft <= thresholdDays;
}

export function buildPlanNextStepGuidance(
    info: LicenceInfo | null | undefined,
    now = new Date(),
): string[] {
    if (!info) {
        return [
            'Next step: enter a licence key and configure your LLM connection.',
        ];
    }

    if (info.plan === 'free') {
        return [
            'Free plan active: the full workflow is available with capped monthly usage.',
            'Next step: start a trial if you want higher-volume evaluation before moving to Developer.',
        ];
    }

    if (info.plan === 'trial') {
        const daysLeft = getDaysUntilExpiry(info.expiresAt, now);
        if (daysLeft !== null && daysLeft <= 2) {
            return [
                `Trial ending soon: ${daysLeft} day${daysLeft === 1 ? '' : 's'} left.`,
                'Next step: upgrade to Developer to keep AI assistant, fix previews, and higher usage after the trial ends.',
            ];
        }

        return [
            'Trial active: the full product workflow is available during evaluation.',
            'Next step: run a real scan, review a finding, and try a fix preview before the trial ends.',
        ];
    }

    if (info.plan === 'developer') {
        return [
            'Developer plan active: the full individual workflow is available.',
            'Next step: keep using Owlvex in your daily scan, explain, and fix loop.',
        ];
    }

    return [
        `Plan active: ${titleCasePlan(info.plan)}.`,
    ];
}

export function isFreePlan(info: LicenceInfo | null | undefined): boolean {
    return info?.plan === 'free';
}

export function hasAiAssistantAccess(info: LicenceInfo | null | undefined): boolean {
    return Boolean(info);
}

export function hasComparisonAccess(info: LicenceInfo | null | undefined): boolean {
    return Boolean(info?.features.comparison);
}

export function hasPromptEditorAccess(info: LicenceInfo | null | undefined): boolean {
    return Boolean(info?.features.promptEditor);
}

export function canRunScan(info: LicenceInfo | null | undefined): boolean {
    if (!info) {
        return false;
    }
    return !info.usage.monthlyLimitReached;
}

export function buildScanLimitMessage(info: LicenceInfo | null | undefined): string {
    if (!info || !info.usage.monthlyLimitReached) {
        return 'Scanning is available.';
    }

    const limit = info.features.scansPerMonth;
    const used = info.usage.scansThisMonth;
    const capText = typeof limit === 'number' ? `${used}/${limit}` : `${used}`;
    return `You have reached this month's scan limit for the ${info.plan} plan (${capText}). Start a trial or upgrade to Developer for higher or unlimited usage.`;
}

export function buildPlanUpgradeMessage(capability: 'assistant' | 'fix' | 'comparison' | 'prompt-editor'): string {
    switch (capability) {
        case 'comparison':
            return 'Scan comparison is not available for this licence. Free normally includes it, so this account may need a trial or Developer upgrade.';
        case 'prompt-editor':
            return 'The guided AI assistant is not available for this licence. Free normally includes it, so this account may need a trial or Developer upgrade.';
        case 'fix':
            return 'AI-assisted fix previews are not available for this licence. Free normally includes them, so this account may need a trial or Developer upgrade.';
        case 'assistant':
        default:
            return 'The AI assistant is not available for this licence. Free normally includes it, so this account may need a trial or Developer upgrade.';
    }
}

export class LicenceManager {
    private info: LicenceInfo | null = null;

    constructor(private readonly secrets: vscode.SecretStorage) {}

    async getKey(): Promise<string | undefined> {
        return this.secrets.get(SECRET_KEY);
    }

    async storeKey(key: string): Promise<void> {
        await this.secrets.store(SECRET_KEY, key);
    }

    async deleteKey(): Promise<void> {
        await this.secrets.delete(SECRET_KEY);
    }

    async validate(apiUrl: string): Promise<LicenceInfo> {
        const key = await this.getKey();
        if (!key) {
            throw new Error('No licence key configured. Run "Owlvex: Enter Licence Key".');
        }

        const res = await fetch(`${apiUrl}/v1/licences/validate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Licence-Key': key,
            },
            body: JSON.stringify({}),
        });

        if (!res.ok) {
            const body = await res.json().catch(() => ({})) as any;
            throw new Error(body?.detail ?? `Licence validation failed (HTTP ${res.status})`);
        }

        const data = await res.json() as any;

        this.info = {
            valid: data.valid,
            licenceId: data.licence_id,
            teamName: data.team_name,
            plan: data.plan,
            seats: data.seats,
            seatsUsed: data.seats_used,
            features: {
                frameworks: data.features.frameworks,
                scansPerMonth: data.features.scans_per_month ?? data.features.scans_per_day,
                promptEditor: data.features.prompt_editor,
                comparison: data.features.comparison,
                teamPrompts: data.features.team_prompts,
                ciCd: data.features.ci_cd,
                pdfReports: data.features.pdf_reports,
                customRules: data.features.custom_rules,
                sso: data.features.sso,
                industryPacks: data.features.industry_packs,
            },
            usage: {
                scansThisMonth: data.usage?.scans_this_month ?? data.usage?.scans_today ?? 0,
                scansRemaining: data.usage?.scans_remaining ?? null,
                monthlyLimitReached: Boolean(data.usage?.monthly_limit_reached ?? data.usage?.daily_limit_reached),
            },
            expiresAt: data.expires_at,
        };

        return this.info;
    }

    getCachedInfo(): LicenceInfo | null {
        return this.info;
    }

    clearCachedInfo(): void {
        this.info = null;
    }

    isFeatureAllowed(feature: keyof LicenceInfo['features']): boolean {
        return !!this.info?.features[feature];
    }

    isFrameworkAllowed(code: string): boolean {
        return this.info?.features.frameworks.includes(code) ?? false;
    }
}
