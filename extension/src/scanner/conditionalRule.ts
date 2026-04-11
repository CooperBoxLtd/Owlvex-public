/**
 * ConditionalRule — the reusable primitive for context-sensitive security rules.
 *
 * Every conditional rule in Owlvex follows this contract:
 *
 *   cheap gate → structural truth → deterministic output
 *
 * Rules with `applicability: 'global'` run on every file and always produce
 * findings when their structural invariant is violated.
 *
 * Rules with `applicability: 'conditional'` are silent on codebases where the
 * architectural context described by `requires` is absent. This is what keeps
 * the engine trustworthy: a multi-tenant isolation rule that fires in a
 * single-tenant codebase is not a signal — it is noise.
 *
 * The two functions encode that separation cleanly:
 *
 *   isApplicable  — file-level gate. If false the rule produces no findings.
 *                   Must be fast (string scan, no regex loops).
 *   evaluate      — structural check. Called only when the gate passes.
 *                   Must be deterministic: identical input → identical output.
 *
 * Example — tenant isolation rule expressed in this shape:
 *
 *   {
 *     id: 'tenant_isolation_missing',
 *     applicability: 'conditional',
 *     requires: ['multi_tenant_context'],
 *
 *     isApplicable: (source) =>
 *       ['tenantId', 'organizationId', 'orgId'].some(s => source.includes(s)),
 *
 *     evaluate: (handler) => {
 *       if (!handler.params.some(p => TENANT_PARAM_RE.test(p))) return [];
 *       if (TENANT_ARG_RE.test(handler.body)) return [];
 *       return [createFinding('tenant_isolation_missing', handler.matchIndex)];
 *     },
 *   }
 */

import type { Finding } from './scanEngine';

/**
 * The context passed to `evaluate` for each match site.
 *
 * For function-level rules (e.g., tenant isolation, IDOR) `body` is the
 * extracted function body text and `params` contains the parsed parameter
 * names. For call-site and file-level rules `body` equals `source` and
 * `params` is empty.
 */
export interface HandlerContext {
    /** Full source text of the file being scanned. */
    source: string;
    /**
     * The text unit under evaluation.
     * - Function-level rules: the extracted function body.
     * - Call-site / file-level rules: the full source.
     */
    body: string;
    /**
     * Parsed function parameter names.
     * Empty array for rules that do not operate on function signatures.
     */
    params: string[];
    /** Byte offset of the match within `source`. */
    matchIndex: number;
}

/**
 * A ConditionalRule encodes the complete reasoning contract for a single
 * context-sensitive security rule. Implementations live in the scanner layer;
 * this interface is the shared contract that governs how they are structured.
 */
export interface ConditionalRule {
    /**
     * Matches `CanonicalIssue.id` in `issueCatalog.ts`.
     * Used for deduplication and finding attribution.
     */
    id: string;
    applicability: 'global' | 'conditional';
    /**
     * Architectural context signals required for this rule to be meaningful.
     * Mirrors `CanonicalIssue.requires`. Present on conditional rules only.
     */
    requires?: string[];
    /**
     * File-level gate. Returns `false` when the source shows no signal that
     * this rule's context is present. When `false` the rule is silent for the
     * entire file — `evaluate` is never called.
     *
     * Keep this cheap: a few `source.includes()` calls, no regex loops.
     */
    isApplicable: (source: string) => boolean;
    /**
     * Per-handler structural check. Called once per matched site when the gate
     * passes. Must be pure and deterministic.
     *
     * Return an empty array to indicate no finding at this site.
     */
    evaluate: (handler: HandlerContext) => Array<Partial<Finding>>;
}
