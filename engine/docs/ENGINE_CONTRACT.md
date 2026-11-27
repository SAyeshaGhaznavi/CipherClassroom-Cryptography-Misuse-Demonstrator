# Engine contract

How members A and C call into the security engine. Everything below is
exported from `src/index.ts`, which is the only file either of you needs to
import from.

## For member A, the API and data layer

### Running an experiment

```ts
import { runExperiment, toSafeError, EngineError } from '../engine/src';

app.post('/api/experiments', requireRole('operator', 'admin'), async (req, res) => {
  try {
    const result = await runExperiment(req.body, {
      actor: req.session.username,
      onAuditEvent: (event) => auditRepository.append(event)
    });
    await experimentRepository.save(result, req.session.username);
    res.json(result);
  } catch (error) {
    const safe = toSafeError(error);
    let status = 400;
    if (error instanceof EngineError) {
      status = error.httpStatus;
    }
    res.status(status).json(safe);
  }
});
```

`runExperiment` either resolves with a result or throws an `EngineError`.
It never resolves with a half finished object. `toSafeError` turns anything
thrown, including an unexpected error, into `{ code, message }` with no
stack trace and no internal path, which is what the specification asks for.

### Error codes and the status each maps to

| Code | Status | Raised when |
| --- | --- | --- |
| `INVALID_INPUT` | 400 | Empty text, control characters, a missing second message |
| `INVALID_PARAMETER` | 400 | A shift outside 0 to 25, an iteration count outside the permitted range |
| `LENGTH_MISMATCH` | 400 | The two nonce reuse messages differ in byte length |
| `POLICY_VIOLATION` | 400 | A configuration change that is not permitted |
| `INPUT_TOO_LARGE` | 413 | Input longer than the configured maximum |
| `UNSUPPORTED_TYPE` | 422 | An experiment type the lab does not offer |
| `FIXTURE_UNAVAILABLE` | 500 | The fixture files could not be located on disk |

### Audit events

Pass `onAuditEvent` and the engine hands back one event per call, for a
successful run and for a rejection alike. The engine does not write them
anywhere. The shape is:

```ts
{
  timestamp: string;
  action: 'experiment.run' | 'experiment.rejected';
  outcome: 'success' | 'failure';
  severity: 'info' | 'warning' | 'critical';
  detail: string;
  resultId: string | null;
  inputDigest: string;
}
```

There is a unit test that checks the submitted plaintext never appears in
one of these.

### Administrator configuration

```ts
import { getPolicy, updatePolicy } from '../engine/src';

app.patch('/api/admin/config', requireRole('admin'), (req, res) => {
  try {
    const outcome = updatePolicy(req.body);
    for (let i = 0; i < outcome.changes.length; i++) {
      const change = outcome.changes[i];
      auditRepository.append({
        timestamp: new Date().toISOString(),
        action: 'config.change',
        outcome: 'success',
        severity: 'warning',
        detail: req.session.username + ' changed ' + change.field +
                ' from ' + change.from + ' to ' + change.to,
        resultId: null,
        inputDigest: ''
      });
    }
    res.json(outcome.policy);
  } catch (error) {
    res.status(400).json(toSafeError(error));
  }
});
```

`updatePolicy` returns the new policy together with a list of exactly what
changed, so one audit event can be written per change. It refuses any field
that is not on the editable list, any value outside its safe bounds, and
any combination that contradicts itself, such as a critical threshold above
the minimum safe threshold.

The editable fields are `maxInputLength`, `criticalKdfIterations`,
`minSafeKdfIterations`, `maxKdfIterations`, `minAvalancheBits`,
`maxAvalancheBits` and `minVigenereKeywordLength`. Every change moves the
policy version forward, and the new version is recorded inside every result
produced afterwards.

One thing to watch: the policy lives in memory in this version, so it
resets when the server restarts. If you want it to survive a restart,
persist it in your repository layer and call `updatePolicy` with the stored
values at startup.

## For member C, the frontend

The result object is already the one your components render. These two
lines are the same type:

```ts
// frontend/src/lib/types.ts
export interface ExperimentResult { id; type; title; timestamp; status; severity;
  summary; details; warnings; evidence; durationMs; version; }

// engine/src/types.ts
export interface ExperimentResult { id; type; title; timestamp; status; severity;
  summary; details; warnings; evidence; durationMs; version; }
```

So nothing in `App.tsx` needs to change when the API goes live. The engine
adds one extra property, `engine`, carrying the rule name, policy version,
thresholds and reasons. It is safe to ignore. If you do want to show it,
the dashboard requirement in the specification asks for evidence and a
recommended action, and `engine.ruleName` plus `engine.reasons` is the
cleanest thing to put there.

The input object is also unchanged. The classical cipher module reads
`mode` for the variant and reuses `secondary` as the Vigenere keyword, so
no new request fields are needed:

| Module | Fields used |
| --- | --- |
| `classical-cipher` | `text`, `shift`, `mode` as `caesar`, `vigenere` or `break`, `secondary` as the keyword when `mode` is `vigenere` |
| `authenticated-encryption` | `text` |
| `hashing-kdfs` | `text`, `iterations` |
| `nonce-reuse` | `text`, `secondary`, both the same byte length |
| `test-vectors` | `text` is accepted but not used |
| `avalanche` | `text`, `iterations` reused as the sample count, 1 to 256 |

The `break` mode is worth a screen of its own. It takes a Caesar
ciphertext and recovers both the shift and the plaintext using letter
frequencies alone, with no key. That is the clearest thing in the whole lab
to put in front of a viewer.

## Supported types

```ts
import { listSupportedTypes } from '../engine/src';
```

Returns the six values the lab offers, which is useful for building a
dropdown or for validating on the server without hardcoding the list twice.

## Running the fixtures yourself

```ts
import { loadSamples, loadVectors } from '../engine/src';
```

`loadSamples()` returns the safe, adverse and malformed sample sets.
Member D can drive the automated suite straight off those rather than
inventing a second set of inputs. The adverse samples each carry an
`expectedIndicator`, which is the rule name the engine must raise, so a
test can assert on something specific rather than just checking that a
warning appeared.
