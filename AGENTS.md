# Repository Guidelines

## Project Structure & Module Organization
The Vite-powered React SPA lives in `src/`, where `main.tsx` bootstraps `App.tsx`. Feature components are grouped by responsibility under `src/components` (for example `RuleVisualization` for the mind map and `IssuesView` for conflict reporting). Rule parsing, processing, and export helpers reside in `src/utils`, while reusable contracts live in `src/types`. Global styles flow from `src/index.css` and Tailwind utilities configured in `tailwind.config.js`; `index.html` provides the single-page shell, and `staticwebapp.config.json` captures Azure Static Web Apps routing and auth defaults.

## Build, Test, and Development Commands
- `npm install` — install dependencies from `package.json`.
- `npm run dev` — start the Vite dev server on port 5173 with HMR.
- `npm run build` — run TypeScript project references and emit a production bundle to `dist/`.
- `npm run preview` — serve the production bundle locally (port 4173) for smoke testing.
- `npm run lint` — execute ESLint with the TypeScript and React presets; fix any issues before pushing.

## Coding Style & Naming Conventions
Author TypeScript modules with 2-space indentation and favor functional components. Keep components, hooks, and directories in `PascalCase`; use `camelCase` for utilities, props, and local state. Surface shared logic through `src/utils` or custom hooks, and define Firewalls-specific schemas in `src/types` so UI layers stay lean. Apply Tailwind classes for styling instead of ad-hoc CSS, and keep variant strings close to the JSX they affect.

## Testing Guidelines
A formal test runner is not wired yet, so document manual QA steps in every PR. Exercise file upload, rule visualization, the issues panel, and the rule editor via `npm run dev`, and ensure the browser console stays clean. If you introduce automated coverage (Vitest + React Testing Library is recommended), store specs under `src/__tests__` and add the command to `package.json`.

## Commit & Pull Request Guidelines
Use sentence-case, imperative commits similar to `Add Azure Static Web Apps CI/CD workflow`. Draft PRs with a concise summary, screenshots for UI shifts, linked issues or Azure work items, and a checklist of lint/tests you ran. Note any schema or configuration changes that require coordination with deployment environments.

## Security & Configuration Tips
The analyzer processes Azure Firewall exports solely in the browser; scrub customer identifiers before sharing sample templates. Keep deployment behavior aligned with `staticwebapp.config.json`, and prefer Azure Static Web Apps configuration for secrets instead of embedding values in the codebase.
