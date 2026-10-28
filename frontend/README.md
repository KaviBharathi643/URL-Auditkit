# URL Audit Kit Frontend

Next.js SOC dashboard frontend for URL Audit Kit.

## Pages
- `/` Dashboard
- `/scanner`
- `/threat-intelligence`
- `/history`
- `/reports`
- `/reports/[scanId]`
- `/indicators`
- `/settings`

## Run
```bash
npm install
npm run dev
```

Default URL: `http://localhost:3000`

## Build
```bash
npm run build
npm start
```

## Backend Integration
The frontend expects FastAPI backend on `http://localhost:8765` by default.

`next.config.mjs` rewrites:
- `/api/*` → backend `/api/*`

Use `.env.local` if needed:
```bash
NEXT_PUBLIC_API_URL=http://localhost:8765
NEXT_PUBLIC_WS_URL=ws://localhost:8765
```
