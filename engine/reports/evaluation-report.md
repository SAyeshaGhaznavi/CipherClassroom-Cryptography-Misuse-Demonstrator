# CipherClassroom evaluation results

Security engine and evaluation fixtures, Member B.

Generated: 2026-11-10T09:53:30.005Z

Engine version: engine-1.0. Policy version at the start of the run: policy-1.0.

Result: 10 of 10 cases passed, 100 percent.

| Case | Title | Status |
| --- | --- | --- |
| T1 | Standard test vectors | PASS |
| T2 | Tampering detection | PASS |
| T3 | Weak password cost | PASS |
| T4 | Nonce reuse | PASS |
| T5 | Avalanche measurement | PASS |
| T6 | Clear misuse warnings | PASS |
| T-final-a | Malformed and oversized input | PASS |
| T-final-b | Safe failure behaviour | PASS |
| T-final-c | Repeated submission | PASS |
| T-final-d | Configuration change and recovery after restart | PASS |

## T1 Standard test vectors

**Status:** PASS

**Input**

10 published vectors from FIPS 180-4, RFC 7914, RFC 6070 parameters, NIST GCM and standard classical examples

**Expected result**

Every vector reproduces the published value exactly

**Actual result**

10 of 10 reproduced, pass rate 100 percent

**Evidence**

```
PASS SHA-256 of the empty string: expected e3b0c44298fc1c...95991b7852b855, actual e3b0c44298fc1c...95991b7852b855
PASS SHA-256 of "abc": expected ba7816bf8f01cf...10ff61f20015ad, actual ba7816bf8f01cf...10ff61f20015ad
PASS SHA-256 of "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq": expected 248d6a61d20638...ecedd419db06c1, actual 248d6a61d20638...ecedd419db06c1
PASS PBKDF2-HMAC-SHA256, 1 iteration, 64 byte output: expected 55ac046e56e308...112041d3a19783, actual 55ac046e56e308...112041d3a19783
PASS PBKDF2-HMAC-SHA256, 4096 iterations, 32 byte output: expected c5e478d59288c8...963873aa98134a, actual c5e478d59288c8...963873aa98134a
PASS AES-128-GCM test case 1, empty plaintext: expected 58e2fccefa7e30...7f1d57a4e7455a, actual 58e2fccefa7e30...7f1d57a4e7455a
PASS AES-128-GCM test case 2, one zero block: expected 0388dace60b6a3...3a67b21257bddf, actual 0388dace60b6a3...3a67b21257bddf
PASS Caesar shift 3 of HELLO: expected KHOOR, actual KHOOR
PASS Caesar shift 13 of ATTACKATDAWN: expected NGGNPXNGQNJA, actual NGGNPXNGQNJA
PASS Vigenere keyword LEMON on ATTACKATDAWN: expected LXFOPVEFRNHR, actual LXFOPVEFRNHR
```

## T2 Tampering detection

**Status:** PASS

**Input**

One AES-256-GCM message, then the same ciphertext with byte 0 XOR 0x01

**Expected result**

The genuine message decrypts and the altered message is rejected without returning plaintext

**Actual result**

Original accepted: Yes. Tampered accepted: No, rejected as expected

**Evidence**

```
Ciphertext with tag, hex: 8b31e42afa9d34fff7635503bff691fe...60430e29b77c2a2a1240424f0ac2da3c
Tampered ciphertext, hex: 8a31e42afa9d34fff7635503bff691fe...60430e29b77c2a2a1240424f0ac2da3c
Original message accepted: Yes
Tampered message accepted: No, rejected as expected
Rejection reason: Authentication tag did not verif...rejected without being returned.
```

## T3 Weak password cost

**Status:** PASS

**Input**

The same password derived at 1000 iterations and at 100000 iterations

**Expected result**

The low cost is reported as critical and names the configured minimum. The configured minimum produces no warning.

**Actual result**

Weak run severity critical rule KDF_COST_BELOW_CRITICAL; strong run severity info rule KDF_COST_ACCEPTABLE

**Evidence**

```
1000 iterations took 1 ms
100000 iterations took 57 ms
The stronger setting is about 57 times slower per guess
Warning text: The iteration count of 1000 is far below the configured minimum of 100000. Password guessing against this setting is cheap.
```

## T4 Nonce reuse

**Status:** PASS

**Input**

Two 16 byte messages encrypted under one AES-GCM key with one nonce used twice

**Expected result**

C1 XOR C2 equals P1 XOR P2, the second message is recovered from the first, and fresh nonces remove the effect

**Actual result**

Relationship Confirmed. Recovered "TRANSFER 900 NOW". Exact: Yes, byte for byte

**Evidence**

```
First ciphertext without tag, hex: 63799b2aa2c819bd0b3fc1bb262bf6fe
Second ciphertext without tag, hex: 63799b2aa2c819bd0b37c1bb262bf6fe
Ciphertext XOR: 00000000000000000008000000000000
Plaintext XOR: 00000000000000000008000000000000
Relationship C1 XOR C2 = P1 XOR P2: Confirmed
Second message recovered from the first: TRANSFER 900 NOW
Recovery exact: Yes, byte for byte
Control run with fresh nonces: No relationship, so the leak is caused by the reused nonce
```

## T5 Avalanche measurement

**Status:** PASS

**Input**

32 single bit flips of the input "CipherClassroom avalanche sample", hashed with SHA-256

**Expected result**

The average number of changed output bits falls between 96 and 160 of 256

**Actual result**

126.5 of 256 (49.41 percent)

**Evidence**

```
Average: 126.5 of 256 (49.41 percent)
Range across samples: 111 to 139 bits
Caesar contrast: 1 of 32 output characters change when one input character changes
Rule applied: AVALANCHE_WITHIN_BAND
```

## T6 Clear misuse warnings

**Status:** PASS

**Input**

5 seeded adverse samples covering weak key derivation, nonce reuse, an ineffective shift, a short keyword and a recoverable classical cipher

**Expected result**

Each sample names the specific indicator that was violated rather than reporting only that the configuration is unsafe

**Actual result**

5 of 5 samples raised the expected named indicator

**Evidence**

```
PASS adverse-01 Key derivation at a negligible cost: expected indicator KDF_COST_BELOW_CRITICAL, actual KDF_COST_BELOW_CRITICAL, severity critical
PASS adverse-02 Nonce reused across two messages: expected indicator NONCE_REUSED_UNDER_SAME_KEY, actual NONCE_REUSED_UNDER_SAME_KEY, severity critical
PASS adverse-03 Caesar shift that performs no encryption: expected indicator CAESAR_SHIFT_INEFFECTIVE, actual CAESAR_SHIFT_INEFFECTIVE, severity critical
PASS adverse-04 Vigenere keyword too short to resist analysis: expected indicator VIGENERE_KEYWORD_TOO_SHORT, actual VIGENERE_KEYWORD_TOO_SHORT, severity critical
PASS adverse-05 Caesar ciphertext recovered without the key: expected indicator CLASSICAL_CIPHER_BROKEN_WITHOUT_KEY, actual CLASSICAL_CIPHER_BROKEN_WITHOUT_KEY, severity critical
```

## T-final-a Malformed and oversized input

**Status:** PASS

**Input**

7 malformed submissions including empty text, a 5000 character body, an out of range shift, an unknown module, mismatched lengths, control characters and an excessive iteration count

**Expected result**

Each submission is refused with its own stable error code and no stack trace

**Actual result**

7 of 7 refused with the expected code

**Evidence**

```
PASS bad-01 Empty input: expected INVALID_INPUT, actual INVALID_INPUT
PASS bad-02 Oversized input: expected INPUT_TOO_LARGE, actual INPUT_TOO_LARGE
PASS bad-03 Shift outside the permitted range: expected INVALID_PARAMETER, actual INVALID_PARAMETER
PASS bad-04 Unknown experiment type: expected UNSUPPORTED_TYPE, actual UNSUPPORTED_TYPE
PASS bad-05 Nonce reuse messages of different lengths: expected LENGTH_MISMATCH, actual LENGTH_MISMATCH
PASS bad-06 Control characters in the input: expected INVALID_INPUT, actual INVALID_INPUT
PASS bad-07 Iteration count above the laptop safety ceiling: expected INVALID_PARAMETER, actual INVALID_PARAMETER
```

## T-final-b Safe failure behaviour

**Status:** PASS

**Input**

An empty submission, then inspection of the error object returned to the caller

**Expected result**

The caller receives only a stable code and a readable message, with no stack trace or internal path

**Actual result**

{"code":"INVALID_INPUT","message":"Input text cannot be empty."}

**Evidence**

```
Safe response shape: {"code":"INVALID_INPUT","message":"Input text cannot be empty."}
Contains a stack frame: no
Contains a source path: no
```

## T-final-c Repeated submission

**Status:** PASS

**Input**

The same experiment submitted five times in succession

**Expected result**

Each run produces its own server generated identifier and its own result record

**Actual result**

Five distinct identifiers were generated

**Evidence**

```
Submission 1 identifier 3742e103-592c-4991-95a9-a974fe3f4d51
Submission 2 identifier 7b4915f5-a2ba-4cff-bd88-17425ad899d1
Submission 3 identifier ec22e0d4-7e3f-470a-95a3-a29c2da50d9b
Submission 4 identifier 6e94fb55-126c-41d7-af0d-9a212bb07b3e
Submission 5 identifier da7a55e1-afb9-4a32-b8a7-6be0aad9386f
```

## T-final-d Configuration change and recovery after restart

**Status:** PASS

**Input**

The same derivation at 120000 iterations, run before a threshold change, after it, and again once the lab returns to its default state

**Expected result**

The result follows the configured threshold, the change is reported for the audit log, and the default state is restored cleanly

**Actual result**

Before: info (policy-1.0); after change: warning (policy-1.0+1); after reset: info (policy-1.0)

**Evidence**

```
Change recorded: minSafeKdfIterations from 100000 to 200000
Baseline rule: KDF_COST_ACCEPTABLE
Rule after the change: KDF_COST_BELOW_MINIMUM
Rule after the reset: KDF_COST_ACCEPTABLE
```
