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
        scansPerDay: number | null;
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
        scansToday: number;
        scansRemaining: number | null;
        dailyLimitReached: boolean;
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

    if (typeof info.features?.scansPerDay === 'number') {
        const scansToday = info.usage?.scansToday ?? 0;
        parts.push(`${scansToday}/${info.features.scansPerDay} scans today`);
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

export function isFreePlan(info: LicenceInfo | null | undefined): boolean {
    return info?.plan === 'free';
}

export function hasAiAssistantAccess(info: LicenceInfo | null | undefined): boolean {
    return !isFreePlan(info);
}

export function hasComparisonAccess(info: LicenceInfo | null | undefined): boolean {
    return Boolean(info?.features.comparison);
}

export function hasPromptEditorAccess(info: LicenceInfo | null | undefined): boolean {
    return Boolean(info?.features.promptEditor) || hasAiAssistantAccess(info);
}

export function canRunScan(info: LicenceInfo | null | undefined): boolean {
    if (!info) {
        return true;
    }
    return !info.usage.dailyLimitReached;
}

export function buildScanLimitMessage(info: LicenceInfo | null | undefined): string {
    if (!info || !info.usage.dailyLimitReached) {
        return 'Scanning is available.';
    }

    const limit = info.features.scansPerDay;
    const used = info.usage.scansToday;
    const capText = typeof limit === 'number' ? `${used}/${limit}` : `${used}`;
    return `You have reached today's scan limit for the ${info.plan} plan (${capText}). Start a trial or upgrade to Developer for higher or unlimited usage.`;
}

export function buildPlanUpgradeMessage(capability: 'assistant' | 'fix' | 'comparison' | 'prompt-editor'): string {
    switch (capability) {
        case 'comparison':
            return 'Scan comparison is part of the Trial, Developer, or Team plans. Free still includes deterministic scanning and reports.';
        case 'prompt-editor':
            return 'The guided AI assistant is part of the Trial or Developer plans. Free still includes deterministic scanning and report generation.';
        case 'fix':
            return 'AI-assisted fix previews are part of the Trial or Developer plans. Free still includes deterministic scanning and report generation.';
        case 'assistant':
        default:
            return 'The AI assistant is part of the Trial or Developer plans. Free still includes deterministic scanning and report generation.';
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
                scansPerDay: data.features.scans_per_day,
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
                scansToday: data.usage?.scans_today ?? 0,
                scansRemaining: data.usage?.scans_remaining ?? null,
                dailyLimitReached: Boolean(data.usage?.daily_limit_reached),
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
