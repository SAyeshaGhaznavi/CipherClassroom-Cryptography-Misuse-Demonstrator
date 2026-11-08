# Proposed API contract

The proposal requires authentication, execution, result retrieval, admin actions, and reports. The URLs and JSON shape below are a **suggested interface**, not mandated exact paths.

Base URL: `http://localhost:3001/api`

## Routes

| Method | Endpoint | Allowed roles | Purpose |
|---|---|---|---|
| POST | `/auth/login` | public | Authenticate; return server-verified user and establish session |
| POST | `/auth/logout` | signed in | End session |
| GET | `/auth/me` | signed in | Load current role after refresh |
| POST | `/experiments` | operator, admin | Validate and run experiment |
| GET | `/experiments` | signed in | Retrieve authorized experiment history |
| GET | `/experiments/:id` | authorized | Retrieve one experiment |
| GET | `/admin/audit` | admin | View append-only audit events |
| PATCH | `/admin/config` | admin | Update permitted lab policy, with audit |
| GET | `/reports/:id/export` | authorized | Export sanitized report (optional server route) |

### POST `/experiments` request

```json
{
  "type": "classical-cipher",
  "text": "HELLO",
  "shift": 3
}
```

Supported `type` values:
`classical-cipher`, `authenticated-encryption`, `hashing-kdfs`, `nonce-reuse`, `test-vectors`, `avalanche`.

### Response format (ExperimentResult)

```json
{
  "id": "server-generated-uuid",
  "type": "classical-cipher",
  "title": "Classical cipher",
  "timestamp": "2026-11-07T00:00:00.000Z",
  "status": "completed",
  "severity": "warning",
  "summary": "Caesar cipher is not secure for modern confidentiality.",
  "details": [{"label":"Ciphertext","value":"KHOOR"}],
  "warnings": ["Do not use this for actual protection."],
  "evidence": [{"name":"Algorithm","value":"Caesar shift 3"}],
  "durationMs": 2.5,
  "version": "engine-1.0"
}
```

### Error response

Return safe error codes and messages, without stack traces:

```json
{"code":"INVALID_INPUT","message":"Shift must be between 0 and 25."}
```

### Division of ownership
- **A:** Backend authentication, sessions, role checks, API, storage, audit, report access.
- **B:** Independent security-engine functions, test vectors, positive/negative/misuse fixtures, measured verification.
- **C:** All present frontend components and report UX; connect service methods to API and test UI workflows.

### Integration caveats
- The current `api.ts` expects `POST /auth/login` to return a `{username,role}` object. Coordinate real credentials and session refresh before replacing demo mode.
- Use server-side input validation, and never trust client-side role state.
- Under cookie sessions, ensure CSRF protection and authorized CORS origins.
- Do not store plaintext, passwords, raw keys, nonces tied to secret sessions, or excess user input in logs.
- Prefer server-provided sanitized report exports over the temporary client-side export.
