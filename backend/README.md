# CipherClassroom backend (Member A)

Backend, data and authentication for **CipherClassroom: Cryptography Misuse Demonstrator**.

In the layered architecture from the project requirements this folder is:

- **Layer 2, API/service layer:** authentication, authorization, business rules, safe errors
- **Layer 4, repository layer:** application records and append-only audit events

It uses the security engine in `../engine` (Member B) as described in
`engine/docs/ENGINE_CONTRACT.md`, and serves the API described in
`docs/API_CONTRACT.md` for the frontend (Member C).

Stack: Node.js, Express, TypeScript, SQLite.

## Setup (VS Code terminal, Windows)

Requires Node.js 22 LTS (the same version the frontend recommends).

```powershell
cd backend
npm install             # also installs and builds ../engine
copy .env.example .env
npm run seed            # creates the admin, operator and viewer accounts
npm run dev             # API at http://localhost:3001/api
```

`npm run seed` prints a random password for every account whose
`SEED_..._PASSWORD` is empty in `.env`. **It is shown only once.**

| Command | What it does |
| --- | --- |
| `npm run dev` | Start the API |
| `npm test` | Run the automated tests |
| `npm run seed` | Create the three accounts |
| `npm run reset-password -- admin` | Give an account a new password (recovery) |

The database is one file: `backend/data/cipherclassroom.db`.

## Roles

| Role | Allowed |
| --- | --- |
| `admin` | Run experiments, read history, export reports, view the audit log, change the lab configuration |
| `operator` | Run experiments, read history, export reports |
| `viewer` | Read history and export reports (read-only) |

Roles are checked by the server on every request. The role always comes from
the database; a role sent by the browser is ignored.

## API endpoints

These are the routes from `docs/API_CONTRACT.md`. Base URL: `http://localhost:3001/api`

| Method | Endpoint | Allowed roles | Purpose |
| --- | --- | --- | --- |
| POST | `/auth/login` | public | Log in. Returns `{ username, role, csrfToken, expiresAt }` and sets the session cookie |
| POST | `/auth/logout` | signed in | End the session |
| GET | `/auth/me` | signed in | Current user, after a page refresh |
| POST | `/experiments` | operator, admin | Validate and run an experiment |
| GET | `/experiments` | signed in | Experiment history, newest first |
| GET | `/experiments/:id` | signed in | One experiment |
| GET | `/admin/audit` | admin | Audit events, newest first |
| PATCH | `/admin/config` | admin | Change a permitted lab policy value |
| GET | `/reports/:id/export` | signed in | Download a sanitized report |

Opening `http://localhost:3001/api` in a browser shows `"status": "running"` and
this list of endpoints, so you can check that the server is up.

**CSRF token:** every `POST`/`PATCH` except login must send the `csrfToken`
from the login response in the `X-CSRF-Token` header.

**Confirmation:** `PATCH /admin/config` must include `"confirm": true`, for example
`{ "minSafeKdfIterations": 200000, "confirm": true }`.

### Errors

Every error is `{ "code": "...", "message": "..." }`, never a stack trace.

| Status | Code | When |
| --- | --- | --- |
| 400 | `INVALID_INPUT` | Missing or wrong field, or the body is not valid JSON |
| 400 | `INVALID_PARAMETER`, `LENGTH_MISMATCH`, `POLICY_VIOLATION` | Refused by the engine |
| 400 | `CONFIRMATION_REQUIRED` | Configuration change without `"confirm": true` |
| 401 | `INVALID_CREDENTIALS` | Wrong username or password (same message for both) |
| 401 | `UNAUTHENTICATED` | Not logged in, or the session expired |
| 403 | `FORBIDDEN` | The role is not allowed |
| 403 | `CSRF_FAILED` | Missing or wrong `X-CSRF-Token` |
| 404 | `NOT_FOUND` | Unknown experiment or route |
| 413 | `INPUT_TOO_LARGE` | Body over 16 kB, or text longer than the lab policy allows |
| 422 | `UNSUPPORTED_TYPE` | Unknown experiment type |
| 429 | `RATE_LIMITED` | Too many requests |
| 500 | `INTERNAL_ERROR` | Unexpected error (details only in the server console) |

## Data model

| Table | Holds |
| --- | --- |
| `users` | id, username, password hash (scrypt), role |
| `sessions` | SHA-256 of the session token, user, CSRF token, expiry time |
| `experiments` | The engine result, stored as returned, with who ran it and when |
| `audit_events` | The audit log. Database triggers block every update and delete |
| `settings` | The saved lab policy, so it survives a restart |

### Audit events

The event format is the one in `ENGINE_CONTRACT.md`, plus `id` and `actor`:

```json
{
  "id": "uuid", "timestamp": "2026-11-17T10:00:00.000Z", "actor": "admin",
  "action": "config.change", "outcome": "success", "severity": "warning",
  "detail": "admin changed minSafeKdfIterations from 100000 to 200000",
  "resultId": null, "inputDigest": ""
}
```

What is logged (as listed in the project requirements):

| Requirement | Actions |
| --- | --- |
| Login | `login.success`, `login.failure`, `logout` |
| Configuration change | `config.change`, `config.rejected` |
| Submission and decision | `experiment.run`, `experiment.rejected` (from the engine) |
| Export | `report.export` |
| Failure | `access.denied`, `csrf.rejected`, `rate_limit.exceeded`, `request.rejected`, `server.error` |
| Administrative activity | `audit.view`, `user.created`, `user.password_reset` |

Passwords, session tokens and submitted text are never written to the log.
For a login with an unknown username, the typed name is not logged either.

## Security

| # | Threat | Mitigation |
| --- | --- | --- |
| 1 | Stolen database reveals passwords | Passwords hashed with scrypt and a random salt |
| 2 | Stolen database reveals sessions | Only the SHA-256 of each session token is stored |
| 3 | Password guessing | Login rate limit: 10 failed attempts per 15 minutes per address |
| 4 | Session stolen by page scripts | Cookie is `HttpOnly` and `SameSite=Strict`; `Secure` when `COOKIE_SECURE=true` |
| 5 | Cross-site request forgery | Per-session CSRF token in `X-CSRF-Token`; CORS only allows the frontend address |
| 6 | User acting above their role | Role checked on the server for every protected route; denial is logged |
| 7 | SQL injection | Every query uses `?` placeholders |
| 8 | Malformed or oversized input | 16 kB body limit, field type checks, then the engine's own validation |
| 9 | Internal details leaking in errors | Only `{ code, message }` is returned |
| 10 | Audit log tampering | Database triggers block updates and deletes |
| 11 | Session that never ends | Sessions expire after `SESSION_HOURS` (default 8) |
| 12 | Accidental configuration change | Admin only, CSRF token and `"confirm": true` required |

Secrets (seed passwords, settings) live in `.env`, which git ignores. The server
listens on `127.0.0.1`, so only this computer can reach it.

## Recovery

| Situation | What to do |
| --- | --- |
| Server restarted | Nothing. Accounts, sessions, history, audit log and lab policy are in the database. |
| Password lost | `npm run reset-password -- admin` prints a new password and logs the account out everywhere. |
| Start again with an empty lab | Stop the server, delete `data/cipherclassroom.db`, run `npm run seed`. |

## Connecting the frontend

The backend is ready: `test/frontend.test.ts` replays the frontend's own
requests from `http://localhost:5173` and passes. These changes are in
Member C's code (`frontend/src/lib/api.ts` and `App.tsx`):

### Needed for the frontend to work with the API

1. Create `frontend/.env` with `VITE_DEMO_MODE=false` and `VITE_API_BASE_URL=http://localhost:3001/api`.
2. Login: add a password field and send `{ username, password }` to `POST /auth/login`.
   The role dropdown is not needed; the server reads the role from the database.
3. CSRF: keep `csrfToken` from the login response and send it as the
   `X-CSRF-Token` header on every `POST` and `PATCH` (except login).
4. Logout: call `POST /auth/logout` (with the CSRF header) before clearing the user.

### Needed to meet the project requirements

1. After a page refresh, call `GET /auth/me` to get the user and a fresh
   `csrfToken` back, instead of showing the login page again.
2. Export: use `GET /reports/:id/export`. In API mode `api.log()` does nothing,
   so the browser-side export is not written to the audit log; the server
   route is ("Log ... export").
3. Admin: add a form that sends `PATCH /admin/config` with
   `{ "<field>": <value>, "confirm": true }` after a confirmation dialog. The
   response is the full new policy. This is needed for the demonstration in the
   requirements: "An administrator changes one permitted rule or threshold,
   repeats the test, and demonstrates that both the new result and
   configuration change are traceable."

### Good to know

- Open the frontend at `http://localhost:5173`, not `127.0.0.1` or a network
  address. Otherwise the browser does not send the session cookie and CORS refuses it.
- Error responses are `{ code, message }`; `api.ts` already shows `message`.
- The demo-only "Reset" button on the Admin page has no API route, because the
  audit log is append-only.
