# Next.js Migration Playbook (Spec-First, Copilot-Driven)

This repository is currently a production Flask app. Use this playbook to implement a controlled migration to a production-grade Next.js + TypeScript application.

## 1) Scope Decision (must be finalized first)

Choose one option and lock it before generating code:

- **Option A: Full rewrite to Next.js**
  - Build new app structure in parallel.
  - Migrate detection logic, APIs, auth, and reports.
  - Cut over only after parity and validation.
- **Option B: Keep Flask and improve architecture**
  - No rewrite.
  - Incremental hardening and modularization in current codebase.

**Recommended for this plan:** Option A (full rewrite) with phased delivery and clear acceptance gates.

## 2) Product Decisions (must be explicit before coding)

Record decisions for each:

- Authentication: required for all scans, optional, or anonymous-first
- Detection approach: rule-based, ML-based, or hybrid
- Scan/report retention: none, short-term, long-term
- Export/reporting: CSV/PDF/JSON requirements
- Risk model:
  - categories (e.g., low/medium/high/critical)
  - numeric thresholds per category
  - explainability requirements per score

Do not start code generation until all decisions are locked.

## 3) Phased Implementation Plan (Next.js rewrite)

### Phase 1 — Foundation
- Initialize Next.js 15 + TypeScript app
- Tailwind + UI system setup
- ESLint/Prettier/path aliases
- Environment variable validation
- Global layout, theme, not-found page

### Phase 2 — Detection Engine
- URL feature extraction module
- Redirect and page signal extraction
- Reputation/blacklist adapters
- Scoring engine with typed outputs
- Explainable reasons for final risk

### Phase 3 — Backend + Storage
- Analyze API route
- Prisma schema and migrations
- Auth implementation
- Input validation and rate limiting
- Scan/report persistence

### Phase 4 — Frontend
- Public landing page
- Scan form UX
- Risk result card with explanations
- Dashboard history and reports
- Settings/admin pages

### Phase 5 — Production Hardening
- Unit and integration tests
- Logging and monitoring
- Structured error handling
- Health endpoint
- Deployment configuration
- Architecture/API/security docs

## 4) Definition of Done (applies to every phase)

Phase is complete only when all are true:

- Code compiles
- Tests pass
- Security checks pass
- Environment variables documented
- No placeholder TODOs
- Imports and module boundaries are correct

## 5) Working Method with Copilot

- Use one **master control prompt** to enforce architecture.
- Generate code in small, ordered file batches.
- Validate after each batch.
- Do not skip acceptance gates between phases.

Use `docs/copilot-prompts-nextjs-migration.md` for copy-paste prompts in exact order.
