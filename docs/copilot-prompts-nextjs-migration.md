# Copy-Paste Copilot Prompts (Ordered, File-Batched)

Use these prompts exactly in order. Keep one chat session for continuity.

## 0) Master Control Prompt (paste first)

You are helping me build a production-grade suspicious website detection web application using Next.js 15, TypeScript, Tailwind CSS, Prisma, PostgreSQL, and secure authentication.  
Follow this exact architecture and do not deviate unless necessary:
- app/ for route groups and API routes
- components/ for reusable UI
- features/ for detection, reports, auth, and monitoring logic
- lib/ for environment, database, validation, logging, and security helpers
- prisma/ for schema and migrations
- tests/ for unit and integration tests
- docs/ for architecture and workflow documentation

The app must include:
1. Public landing page.
2. URL analysis form.
3. Risk scoring engine.
4. Explainable reasons for each result.
5. Dashboard with scan history.
6. Reports page.
7. Auth system.
8. Secure API routes.
9. Production validation and error handling.
10. Clean, professional UI.

Build the app in phases. First generate the folder structure, then the database schema, then the detection engine, then the API routes, then the frontend pages, then tests, then documentation.  
Use clean TypeScript, avoid placeholder TODOs, and ensure every major module is complete and working.  
If a decision is needed, choose the simplest production-safe option.  
Keep all code modular and scalable.  
After each file, ensure imports are correct and code compiles.

## 1) Foundation — Prompt A (structure + configs)

Generate only the folder structure and base configs for a Next.js 15 + TypeScript production app.  
Create or update:
- package.json scripts (dev, build, start, lint, test, typecheck, prisma)
- tsconfig.json path aliases
- next.config.ts
- tailwind.config.ts
- .env.example
- app/layout.tsx
- app/not-found.tsx
- app/globals.css

Do not generate feature/business logic yet.

## 2) Foundation — Prompt B (core libs)

Generate only:
- lib/env.ts with strict environment validation
- lib/db.ts with Prisma singleton pattern
- lib/constants.ts
- lib/validators.ts
- lib/security.ts (basic secure helpers)
- lib/logger.ts

Use production-safe defaults and typed exports.

## 3) Data Layer — Prompt C (Prisma)

Generate only:
- prisma/schema.prisma

Requirements:
- Models for users, scans, reports, and audit logs
- Proper relations, enums, timestamps, indexes
- Fields needed for risk score, reasons, and raw URL inputs
- Keep schema ready for PostgreSQL production use

## 4) Detection Engine — Prompt D

Generate only:
- features/detection/types.ts
- features/detection/extractors.ts
- features/detection/scoring.ts
- features/detection/detector.ts

Requirements:
- Typed feature extraction
- Redirect and URL pattern risk signals
- Explainable risk reasons
- Deterministic score output and category

## 5) API Routes — Prompt E

Generate only:
- app/api/analyze/route.ts
- app/api/reports/route.ts
- app/api/health/route.ts

Requirements:
- Input validation
- Consistent JSON error responses
- Rate limit hooks
- Secure defaults and minimal leakage in errors

## 6) Auth — Prompt F

Generate only:
- app/api/auth/[...nextauth]/route.ts
- features/auth/* required files

Requirements:
- Secure session strategy
- Password handling best practices
- Role support for basic admin/report access

## 7) UI — Prompt G (public + dashboard shell)

Generate only:
- app/(public)/page.tsx
- app/(public)/about/page.tsx
- app/(public)/disclaimer/page.tsx
- app/(dashboard)/layout.tsx
- app/(dashboard)/page.tsx
- components/layout/* required files
- components/ui/* required files

Use a clean, professional layout and reusable components.

## 8) UI — Prompt H (flows)

Generate only:
- scan form components
- result card components
- history table components
- app/(dashboard)/scans/page.tsx
- app/(dashboard)/reports/page.tsx
- app/(dashboard)/settings/page.tsx

Keep state and props strongly typed. No placeholder logic.

## 9) Monitoring + Robustness — Prompt I

Generate only:
- features/monitoring/* required files
- server/services/* required files
- server/repositories/* required files

Add structured logging, error mapping, and health-oriented service boundaries.

## 10) Tests — Prompt J

Generate:
- tests/unit/* for detector and scoring logic
- tests/integration/* for analyze API and report flow

Include realistic pass/fail scenarios and malformed input cases.

## 11) Docs — Prompt K

Generate only:
- docs/architecture.md
- docs/api.md
- docs/security.md
- docs/copilot-workflow.md

Document environment variables, error contracts, and deployment assumptions.

## 12) Final Validation Prompt

Now run a final consistency pass across the codebase:
- verify imports and paths,
- remove dead code,
- ensure no TODO placeholders,
- ensure strict TypeScript compatibility,
- ensure all API routes use shared validation and error utilities,
- provide a final checklist of completed modules.
