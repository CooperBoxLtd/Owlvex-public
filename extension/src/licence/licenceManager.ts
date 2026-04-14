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
    expiresAt: string | null;
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
