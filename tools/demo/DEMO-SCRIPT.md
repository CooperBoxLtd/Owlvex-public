# Owlvex — 3-Minute Demo Script

**Format:** live VSCode session, screenshare  
**Audience:** technical founder, security lead, developer team  
**Files:** `tools/demo/01–04`  
**One claim per beat. Three beats total.**

---

## Setup (before the call)

- Open VSCode with this repo loaded
- Have the four demo files open in tabs, in order
- Owlvex sidebar visible on the left
- No findings showing yet (clean state)

---

## Opening (30 seconds)

> "I'm going to show you three things Owlvex does that most security tools don't.
> Not vulnerability lists — reasoning.
> I'll show you what Owlvex knows, how it knows it, and why it stays silent when it should."

Open `01-idor-unsafe.js`. Don't scan yet. Ask:

> "Look at this function for 10 seconds. Can you see the security issue?"

Wait. Most people won't. Some will say "no authentication" — which is partially right but misses the point.

---

## Beat 1 — Proven violation (60 seconds)

**Fixture:** `01-idor-unsafe.js`

```javascript
async function getDocument(currentUser, docId, db) {
    const doc = await db.query(
        'SELECT * FROM documents WHERE id = ?',
        [docId],
    );
    return doc;
}
```

Trigger the scan. Owlvex flags:

```
⚡ AC-001  HIGH  Insecure Direct Object Reference
```

Point to the ⚡ icon and say:

> "That lightning bolt means this wasn't a guess. Owlvex traced a structural invariant:
> `docId` is a caller-supplied parameter. It reaches a database query.
> No ownership check appears in the function body.
> That combination is always a defect — 100% confidence, no false positives."

Read the finding explanation aloud — it should sound like an analyst, not a lint rule.

Now switch to `02-idor-safe.js` and scan:

```javascript
async function getDocument(currentUser, docId, db) {
    const doc = await db.query(
        'SELECT * FROM documents WHERE id = ? AND user_id = ?',
        [docId, currentUser.id],
    );
    return doc;
}
```

**No finding.** Point to the clean sidebar and say:

> "Same scanner. Same rule. Different structure.
> The query now includes `currentUser.id` — the invariant is satisfied.
> Owlvex doesn't flag it. This is not a tool that cries wolf."

**Pause here.** Let the silence land.

---

## Beat 2 — Architectural context (75 seconds)

**Fixture:** `03-debug-unsafe.js`

> "Now let me show you something different.
> This isn't an injection bug. It's a configuration issue — and most scanners either
> miss it entirely or flag it everywhere, including in test files where it doesn't matter."

Open `03-debug-unsafe.js` and scan. Owlvex flags:

```
⚡ SM-002  MEDIUM  Debug Mode Active Without Production Guard
```

Say:

> "The rule fired because Owlvex detected two structural conditions together:
> First — this file references `NODE_ENV`. It's env-aware.
> Second — the debug activation has no `NODE_ENV !== 'production'` guard around it.
> Those two facts together mean debug mode will be active in production."

Now switch to `03-debug-unsafe.js` and point to the `NODE_ENV` reference elsewhere in the file:

> "If `NODE_ENV` weren't referenced here at all, Owlvex would stay silent.
> A test helper that sets debug mode has no concept of production — no flag needed.
> The rule only activates when the code is already env-aware. That's what we call
> a conditional rule. It adapts to your architecture."

Switch to `04-debug-safe.js` and scan:

**No finding.** Say:

> "One if-guard. That's all it takes. The invariant is satisfied."

---

## Beat 3 — Report language (30 seconds)

Generate the report from the two unsafe files. Open it. Read the Attack Surface Assessment aloud:

> "Owlvex identified 2 security vulnerabilities across 2 of 2 scanned files,
> including 1 high-severity exposure requiring immediate attention.
> 2 findings were confirmed by deterministic structural analysis — these are
> invariant violations in the code structure, not probabilistic inferences.
> Each carries 100% confidence and requires no additional validation before escalation."

Then say:

> "That paragraph was written by the engine. Same code, same wording, every run.
> It's not AI phrasing. It's the findings themselves, expressed in language a
> CTO or security lead can read and act on."

---

---

## Optional Beat 2b — Tenant isolation (swap in for SaaS / enterprise audiences)

**Fixture:** `05-tenant-isolation-unsafe.js`

> "If you're building a multi-tenant SaaS product, this is the rule that matters."

Scan. Owlvex flags **CRITICAL**:

```
⚡ AC-T001  CRITICAL  Multi-Tenant Isolation Failure
```

Read the explanation:

> "The function accepts `tenantId` as a parameter that identifies the intended
> tenant scope, but the database query does not include that identifier as a
> WHERE clause constraint. The tenant boundary exists at the API layer but is
> not enforced at the data layer."

Say:

> "That's not a warning. That's a proof.
> Owlvex traced: tenantId arrives as a parameter. Query args don't include it.
> Those two structural facts together mean every tenant can read every other tenant's data.
> This rule is silent in single-tenant codebases — it only activates when it
> sees tenant identity signals in the source. Zero false positives on apps where
> it doesn't apply."

---

## Close (15 seconds)

> "Most security tools give you a list of possible issues.
> Owlvex tells you which ones are proven and explains exactly why.
> That's the difference between noise and signal."

---

## What each beat proves

| Beat | Claim | Evidence |
| --- | --- | --- |
| 1 | Owlvex proves violations, not guesses | AC-001 fires on unsafe, silent on safe |
| 2 | Owlvex adapts to architecture | SM-002 conditional gate, silent on no-env code |
| 3 | Findings translate to business language | Attack surface paragraph — deterministic, consistent |

---

## Handling questions

**"Does it catch everything?"**

> "No — and that's intentional. Deterministic rules only fire when the structural condition is unambiguous. 
> Everything else goes to the AI layer, which handles context that can't be proven by static structure alone.
> We're explicit about which is which. That's the point."

**"What languages does it support?"**

> "JavaScript and TypeScript currently for deterministic rules. The AI layer handles everything else."

**"How does it compare to Snyk / Semgrep?"**

> "Snyk matches known vulnerability patterns in dependencies. Semgrep matches code patterns you write rules for.
> Owlvex reasons about structural invariants — the relationship between data flow and authorization, 
> not just whether a function name matches a list. And it explains the reasoning, not just the result."

**"What's the false positive rate?"**

> "For the deterministic layer — zero by construction. The rule only fires when a structural invariant 
> is verifiably violated. For the AI layer, confidence scores reflect uncertainty. We separate the two 
> so you know exactly which claims need your judgment."
