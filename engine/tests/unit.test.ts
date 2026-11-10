/**
 * Unit tests for the security engine.
 *
 * Positive, negative, edge case and misuse coverage, as the specification
 * requires. Run with: npm test
 */

import { assertEquals, assertRejectsWithCode, assertTrue, assertWithin, group, report, test } from './harness';
import {
  caesarDecrypt,
  caesarEncrypt,
  frequencyBreak,
  indexOfCoincidence,
  vigenereDecrypt,
  vigenereEncrypt
} from '../src/modules/classical';
import {
  decryptText,
  encryptText,
  generateKeyBytes,
  generateNonce,
  tamperWithByte
} from '../src/modules/aead';
import { assessKdfCost, deriveKeyPbkdf2, generateSalt, sha256HexText } from '../src/modules/hashing';
import { compareWithFreshNonces, demonstrateNonceReuse } from '../src/modules/nonceReuse';
import { measureAvalanche } from '../src/modules/avalanche';
import { runTestVectors } from '../src/modules/testVectors';
import { buildMalformedText, loadSamples, loadVectors } from '../fixtures';
import { runExperiment } from '../src/engine';
import { getPolicy, resetPolicy, updatePolicy } from '../src/policy';
import { constantTimeEquals, flipBit, fromHex, hammingDistanceBits, toHex, xorBytes } from '../src/util/bytes';
import { EngineError } from '../src/errors';
import type { ExperimentInput, ExperimentType } from '../src/types';

async function main(): Promise<void> {
  resetPolicy();

  /* -------------------------------------------------- byte utilities */
  group('Byte utilities');

  await test('hex round trip preserves the bytes', () => {
    const original = new Uint8Array([0, 1, 15, 16, 127, 128, 255]);
    const restored = fromHex(toHex(original));
    assertTrue(constantTimeEquals(original, restored), 'Round trip changed the bytes.');
  });

  await test('XOR of a value with itself is zero', () => {
    const value = new Uint8Array([12, 200, 7]);
    const result = xorBytes(value, value);
    for (let i = 0; i < result.length; i++) {
      assertEquals(result[i], 0, 'Byte ' + i + ' was not zero.');
    }
  });

  await test('flipping one bit changes exactly one bit', () => {
    const original = new Uint8Array([0b10101010, 0b00001111]);
    const flipped = flipBit(original, 3);
    assertEquals(hammingDistanceBits(original, flipped), 1, 'More than one bit changed.');
  });

  await test('constant time comparison rejects different lengths', () => {
    const shorter = new Uint8Array([1, 2]);
    const longer = new Uint8Array([1, 2, 3]);
    assertEquals(constantTimeEquals(shorter, longer), false, 'Different lengths compared as equal.');
  });

  /* -------------------------------------------------- classical */
  group('FR-2 Classical cipher');

  await test('Caesar matches the published HELLO vector', () => {
    assertEquals(caesarEncrypt('HELLO', 3), 'KHOOR', 'Caesar output did not match.');
  });

  await test('Caesar round trip returns the original text', () => {
    const original = 'Meet at the library at noon.';
    assertEquals(caesarDecrypt(caesarEncrypt(original, 11), 11), original, 'Round trip failed.');
  });

  await test('Caesar leaves punctuation and spacing untouched', () => {
    assertEquals(caesarEncrypt('A, B!', 1), 'B, C!', 'Non letter characters were altered.');
  });

  await test('Caesar shift 0 performs no encryption, which is the misuse case', () => {
    assertEquals(caesarEncrypt('SECRET', 0), 'SECRET', 'Shift 0 unexpectedly changed the text.');
  });

  await test('Vigenere matches the published LEMON vector', () => {
    assertEquals(vigenereEncrypt('ATTACKATDAWN', 'LEMON'), 'LXFOPVEFRNHR', 'Vigenere output did not match.');
  });

  await test('Vigenere round trip returns the original text', () => {
    const original = 'ATTACKATDAWN';
    assertEquals(vigenereDecrypt(vigenereEncrypt(original, 'LEMON'), 'LEMON'), original, 'Round trip failed.');
  });

  await test('frequency analysis recovers a Caesar shift without the key', () => {
    const plaintext =
      'THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG WHILE THE TREASURE REMAINS BURIED UNDER THE OLD OAK TREE NEAR THE RIVER';
    const ciphertext = caesarEncrypt(plaintext, 7);
    const broken = frequencyBreak(ciphertext);
    assertEquals(broken.recoveredShift, 7, 'The attack did not recover the correct shift.');
    assertEquals(broken.recoveredPlaintext, plaintext, 'The recovered plaintext did not match.');
  });

  await test('index of coincidence of English text is near 0.067', () => {
    const english =
      'THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG AND THEN RETURNS TO THE RIVER BANK WHERE THE TREASURE WAS BURIED LONG AGO';
    assertWithin(indexOfCoincidence(english), 0.05, 0.09, 'Index of coincidence was outside the English range.');
  });

  /* -------------------------------------------------- AEAD */
  group('FR-3 Authenticated encryption');

  await test('AES-GCM decrypts its own ciphertext', async () => {
    const key = await generateKeyBytes();
    const nonce = generateNonce();
    const ciphertext = await encryptText(key, nonce, 'Attendance sheet for lab session four.');
    const outcome = await decryptText(key, nonce, ciphertext);
    assertTrue(outcome.accepted, 'A genuine message was rejected.');
    assertEquals(outcome.plaintext, 'Attendance sheet for lab session four.', 'Plaintext did not round trip.');
  });

  await test('a single flipped ciphertext bit is rejected', async () => {
    const key = await generateKeyBytes();
    const nonce = generateNonce();
    const ciphertext = await encryptText(key, nonce, 'Transfer approved.');
    const tampered = tamperWithByte(ciphertext, 0, 0x01);
    const outcome = await decryptText(key, nonce, tampered);
    assertEquals(outcome.accepted, false, 'A tampered message was accepted.');
    assertEquals(outcome.plaintext, null, 'Plaintext was returned for a tampered message.');
  });

  await test('a flipped authentication tag bit is rejected', async () => {
    const key = await generateKeyBytes();
    const nonce = generateNonce();
    const ciphertext = await encryptText(key, nonce, 'Transfer approved.');
    const tampered = tamperWithByte(ciphertext, ciphertext.length - 1, 0x80);
    const outcome = await decryptText(key, nonce, tampered);
    assertEquals(outcome.accepted, false, 'A message with a modified tag was accepted.');
  });

  await test('the wrong nonce is rejected', async () => {
    const key = await generateKeyBytes();
    const nonce = generateNonce();
    const other = generateNonce();
    const ciphertext = await encryptText(key, nonce, 'Transfer approved.');
    const outcome = await decryptText(key, other, ciphertext);
    assertEquals(outcome.accepted, false, 'Decryption succeeded with the wrong nonce.');
  });

  await test('the wrong key is rejected', async () => {
    const key = await generateKeyBytes();
    const otherKey = await generateKeyBytes();
    const nonce = generateNonce();
    const ciphertext = await encryptText(key, nonce, 'Transfer approved.');
    const outcome = await decryptText(otherKey, nonce, ciphertext);
    assertEquals(outcome.accepted, false, 'Decryption succeeded with the wrong key.');
  });

  await test('truncated ciphertext is rejected without throwing', async () => {
    const key = await generateKeyBytes();
    const nonce = generateNonce();
    const outcome = await decryptText(key, nonce, new Uint8Array([1, 2, 3]));
    assertEquals(outcome.accepted, false, 'Truncated input was accepted.');
  });

  /* -------------------------------------------------- hashing */
  group('FR-4 Hashing and key derivation');

  await test('SHA-256 of "abc" matches the published digest', async () => {
    const digest = await sha256HexText('abc');
    assertEquals(digest, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'Digest mismatch.');
  });

  await test('SHA-256 is deterministic for the same input', async () => {
    const first = await sha256HexText('CipherClassroom');
    const second = await sha256HexText('CipherClassroom');
    assertEquals(first, second, 'The same input produced two different digests.');
  });

  await test('a different salt gives a different derived key for one password', async () => {
    const saltA = generateSalt();
    const saltB = generateSalt();
    const first = await deriveKeyPbkdf2('password', saltA, 2000);
    const second = await deriveKeyPbkdf2('password', saltB, 2000);
    assertEquals(
      constantTimeEquals(first.derivedKey, second.derivedKey),
      false,
      'Two different salts produced the same derived key.'
    );
  });

  await test('the same salt and password reproduce the same derived key', async () => {
    const salt = generateSalt();
    const first = await deriveKeyPbkdf2('password', salt, 2000);
    const second = await deriveKeyPbkdf2('password', salt, 2000);
    assertTrue(constantTimeEquals(first.derivedKey, second.derivedKey), 'Derivation was not reproducible.');
  });

  await test('a negligible iteration count is reported as critical', async () => {
    const policy = getPolicy();
    const outcome = await deriveKeyPbkdf2('summer2024', generateSalt(), 1000);
    const assessment = assessKdfCost(outcome, policy);
    assertEquals(assessment.severity, 'critical', 'A weak cost was not flagged as critical.');
    assertTrue(assessment.warnings.length > 0, 'No warning text was produced.');
  });

  await test('the configured minimum iteration count produces no warning', async () => {
    const policy = getPolicy();
    const outcome = await deriveKeyPbkdf2('correct horse battery staple', generateSalt(), policy.minSafeKdfIterations);
    const assessment = assessKdfCost(outcome, policy);
    assertEquals(assessment.severity, 'info', 'An acceptable cost was flagged.');
  });

  /* -------------------------------------------------- nonce reuse */
  group('FR-5 Nonce reuse');

  await test('reusing a nonce makes C1 XOR C2 equal P1 XOR P2', async () => {
    const evidence = await demonstrateNonceReuse('TRANSFER 100 NOW', 'TRANSFER 900 NOW');
    assertTrue(evidence.relationshipHolds, 'The keystream did not cancel as expected.');
    assertEquals(evidence.ciphertextXorHex, evidence.plaintextXorHex, 'The two XOR values differed.');
  });

  await test('the second message is recovered exactly from the first', async () => {
    const evidence = await demonstrateNonceReuse('TRANSFER 100 NOW', 'TRANSFER 900 NOW');
    assertTrue(evidence.recoveryExact, 'Recovery was not byte for byte.');
    assertEquals(evidence.recoveredSecondMessage, 'TRANSFER 900 NOW', 'The recovered message was wrong.');
  });

  await test('fresh nonces remove the relationship, isolating the cause', async () => {
    const control = await compareWithFreshNonces('TRANSFER 100 NOW', 'TRANSFER 900 NOW');
    assertEquals(control.relationshipHolds, false, 'The relationship survived fresh nonces.');
  });

  await test('messages of different lengths are refused by the module', async () => {
    let threw = false;
    try {
      await demonstrateNonceReuse('SHORT', 'A MUCH LONGER MESSAGE');
    } catch (error) {
      threw = true;
    }
    assertTrue(threw, 'Mismatched lengths were accepted.');
  });

  /* -------------------------------------------------- avalanche */
  group('T5 Avalanche');

  await test('SHA-256 changes about half of its output bits', async () => {
    const report = await measureAvalanche('CipherClassroom avalanche sample', 24, getPolicy());
    assertWithin(report.averageChangedBits, 96, 160, 'The average was outside the expected band.');
    assertTrue(report.withinPolicyBand, 'The measurement fell outside the configured policy band.');
  });

  await test('no single sample leaves every output bit unchanged', async () => {
    const report = await measureAvalanche('CipherClassroom avalanche sample', 16, getPolicy());
    assertTrue(report.minimumChangedBits > 0, 'One sample produced an identical digest.');
  });

  /* -------------------------------------------------- vectors */
  group('FR-6 Published test vectors');

  await test('every published vector reproduces exactly', async () => {
    const summary = await runTestVectors(loadVectors());
    assertEquals(summary.failed, 0, summary.failed + ' vector(s) failed to reproduce.');
    assertTrue(summary.total >= 10, 'Fewer vectors ran than expected.');
  });

  /* -------------------------------------------------- validation */
  group('Input validation and safe failure');

  await test('empty input is rejected with INVALID_INPUT', async () => {
    await assertRejectsWithCode(
      () => runExperiment({ type: 'classical-cipher', text: '' }),
      'INVALID_INPUT',
      'Empty input was not rejected correctly.'
    );
  });

  await test('oversized input is rejected with INPUT_TOO_LARGE', async () => {
    let oversized = '';
    for (let i = 0; i < 5000; i++) {
      oversized = oversized + 'A';
    }
    await assertRejectsWithCode(
      () => runExperiment({ type: 'classical-cipher', text: oversized }),
      'INPUT_TOO_LARGE',
      'Oversized input was not rejected correctly.'
    );
  });

  await test('an out of range shift is rejected with INVALID_PARAMETER', async () => {
    await assertRejectsWithCode(
      () => runExperiment({ type: 'classical-cipher', text: 'HELLO', shift: 99 }),
      'INVALID_PARAMETER',
      'An invalid shift was accepted.'
    );
  });

  await test('an unknown experiment type is rejected with UNSUPPORTED_TYPE', async () => {
    await assertRejectsWithCode(
      () => runExperiment({ type: 'rsa-factoring' as ExperimentType, text: 'HELLO' }),
      'UNSUPPORTED_TYPE',
      'An unknown type was accepted.'
    );
  });

  await test('mismatched nonce reuse lengths are rejected with LENGTH_MISMATCH', async () => {
    await assertRejectsWithCode(
      () => runExperiment({ type: 'nonce-reuse', text: 'SHORT', secondary: 'A MUCH LONGER MESSAGE' }),
      'LENGTH_MISMATCH',
      'Mismatched lengths were accepted.'
    );
  });

  await test('control characters are rejected', async () => {
    await assertRejectsWithCode(
      () => runExperiment({ type: 'classical-cipher', text: 'HELLO' + String.fromCharCode(7) + 'WORLD' }),
      'INVALID_INPUT',
      'Control characters were accepted.'
    );
  });

  await test('an error response carries a code and a message but no stack trace', async () => {
    let captured: EngineError | null = null;
    try {
      await runExperiment({ type: 'classical-cipher', text: '' });
    } catch (error) {
      if (error instanceof EngineError) {
        captured = error;
      }
    }
    assertTrue(captured !== null, 'No EngineError was thrown.');
    if (captured !== null) {
      const safe = captured.toSafeResponse();
      const keys = Object.keys(safe);
      assertEquals(keys.length, 2, 'The safe response exposed more than a code and a message.');
      assertTrue(String(JSON.stringify(safe)).indexOf('at ') === -1, 'The safe response looks like it contains a stack trace.');
    }
  });

  /* -------------------------------------------------- misuse detection */
  group('T6 Misuse warnings');

  await test('a zero Caesar shift is reported as critical with a named rule', async () => {
    const result = await runExperiment({ type: 'classical-cipher', text: 'PLAINTEXT STAYS PLAIN', shift: 0 });
    assertEquals(result.severity, 'critical', 'The ineffective shift was not critical.');
    assertEquals(result.engine.ruleName, 'CAESAR_SHIFT_INEFFECTIVE', 'The rule name was wrong.');
    assertTrue(result.warnings.length > 0, 'No warning was attached.');
  });

  await test('a short Vigenere keyword is named rather than reported only as unsafe', async () => {
    const result = await runExperiment({
      type: 'classical-cipher',
      text: 'THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG',
      secondary: 'AB',
      mode: 'vigenere'
    });
    assertEquals(result.engine.ruleName, 'VIGENERE_KEYWORD_TOO_SHORT', 'The rule name was wrong.');
    assertTrue(
      result.warnings.join(' ').indexOf(String(getPolicy().minVigenereKeywordLength)) !== -1,
      'The warning did not quote the configured minimum.'
    );
  });

  await test('a weak key derivation cost names the threshold it failed', async () => {
    const result = await runExperiment({ type: 'hashing-kdfs', text: 'summer2024', iterations: 1000 });
    assertEquals(result.engine.ruleName, 'KDF_COST_BELOW_CRITICAL', 'The rule name was wrong.');
    assertTrue(
      result.warnings.join(' ').indexOf(String(getPolicy().minSafeKdfIterations)) !== -1,
      'The warning did not quote the configured minimum.'
    );
  });

  /* -------------------------------------------------- reproducibility */
  group('Reproducibility metadata');

  await test('every result records a rule name, policy version and thresholds', async () => {
    const result = await runExperiment({ type: 'classical-cipher', text: 'HELLO', shift: 3 });
    assertTrue(result.engine.ruleName.length > 0, 'No rule name was recorded.');
    assertTrue(result.engine.policyVersion.length > 0, 'No policy version was recorded.');
    assertTrue(Object.keys(result.engine.thresholds).length > 0, 'No thresholds were recorded.');
    assertTrue(result.engine.reasons.length > 0, 'No reasons were recorded.');
  });

  await test('the plaintext is not stored in the reproducibility metadata', async () => {
    const secret = 'DO NOT STORE THIS SENTENCE';
    const result = await runExperiment({ type: 'hashing-kdfs', text: secret, iterations: 1000 });
    const serialised = JSON.stringify(result.engine);
    assertEquals(serialised.indexOf(secret), -1, 'The input was copied into the stored metadata.');
    assertEquals(result.engine.inputDigest.length, 16, 'The input digest prefix was the wrong length.');
  });

  await test('each result is given a distinct server side identifier', async () => {
    const first = await runExperiment({ type: 'classical-cipher', text: 'HELLO', shift: 3 });
    const second = await runExperiment({ type: 'classical-cipher', text: 'HELLO', shift: 3 });
    assertTrue(first.id !== second.id, 'Two results shared one identifier.');
  });

  /* -------------------------------------------------- policy */
  group('Administrator policy changes');

  await test('a permitted threshold change is applied and reported', () => {
    resetPolicy();
    const before = getPolicy().minSafeKdfIterations;
    const outcome = updatePolicy({ minSafeKdfIterations: 200000 });
    assertEquals(outcome.policy.minSafeKdfIterations, 200000, 'The change was not applied.');
    assertEquals(outcome.changes.length, 1, 'The change was not reported for the audit log.');
    assertEquals(outcome.changes[0].from, String(before), 'The previous value was not recorded.');
    resetPolicy();
  });

  await test('a policy change moves the policy version forward', () => {
    resetPolicy();
    const before = getPolicy().policyVersion;
    const outcome = updatePolicy({ minSafeKdfIterations: 150000 });
    assertTrue(outcome.policy.policyVersion !== before, 'The policy version did not change.');
    resetPolicy();
  });

  await test('the same result changes severity after the threshold is raised', async () => {
    resetPolicy();
    const before = await runExperiment({ type: 'hashing-kdfs', text: 'password', iterations: 120000 });
    assertEquals(before.severity, 'info', 'The baseline run was not informational.');
    updatePolicy({ minSafeKdfIterations: 200000 });
    const after = await runExperiment({ type: 'hashing-kdfs', text: 'password', iterations: 120000 });
    assertEquals(after.severity, 'warning', 'The raised threshold did not change the outcome.');
    assertTrue(after.engine.policyVersion !== before.engine.policyVersion, 'The result did not record the new policy version.');
    resetPolicy();
  });

  await test('a field that is not editable is refused', () => {
    resetPolicy();
    let code = '';
    try {
      updatePolicy({ policyVersion: 9 });
    } catch (error) {
      if (error instanceof EngineError) {
        code = error.code;
      }
    }
    assertEquals(code, 'POLICY_VIOLATION', 'An unauthorised field was accepted.');
    resetPolicy();
  });

  await test('a contradictory threshold pair is refused', () => {
    resetPolicy();
    let code = '';
    try {
      updatePolicy({ criticalKdfIterations: 500000 });
    } catch (error) {
      if (error instanceof EngineError) {
        code = error.code;
      }
    }
    assertEquals(code, 'POLICY_VIOLATION', 'A contradictory policy was accepted.');
    resetPolicy();
  });

  /* -------------------------------------------------- audit */
  group('Audit events');

  await test('a successful run offers one audit event with no plaintext', async () => {
    const events: string[] = [];
    const secret = 'AUDIT SECRET SENTENCE';
    await runExperiment(
      { type: 'classical-cipher', text: secret, shift: 5 },
      {
        actor: 'operator-demo',
        onAuditEvent: (event) => {
          events.push(JSON.stringify(event));
        }
      }
    );
    assertEquals(events.length, 1, 'Exactly one audit event was expected.');
    assertEquals(events[0].indexOf(secret), -1, 'The audit event contained the plaintext.');
    assertTrue(events[0].indexOf('operator-demo') !== -1, 'The audit event did not record the actor.');
  });

  await test('a rejected submission is also offered as an audit event', async () => {
    const events: string[] = [];
    try {
      await runExperiment(
        { type: 'classical-cipher', text: '' },
        { actor: 'operator-demo', onAuditEvent: (event) => { events.push(event.action); } }
      );
    } catch (error) {
      // The rejection itself is expected.
    }
    assertEquals(events.length, 1, 'The rejection was not recorded.');
    assertEquals(events[0], 'experiment.rejected', 'The wrong audit action was recorded.');
  });

  /* -------------------------------------------------- fixtures */
  group('Fixture layer');

  await test('all safe samples complete without a critical finding', async () => {
    const samples = loadSamples().safe;
    for (let i = 0; i < samples.length; i++) {
      const sample = samples[i];
      const input: ExperimentInput = {
        type: sample.type as ExperimentType,
        text: sample.text,
        secondary: sample.secondary,
        shift: sample.shift,
        iterations: sample.iterations,
        mode: sample.mode
      };
      const result = await runExperiment(input);
      assertTrue(result.severity !== 'critical', 'Safe sample ' + sample.id + ' produced a critical finding.');
      assertEquals(result.status, 'completed', 'Safe sample ' + sample.id + ' did not complete.');
    }
  });

  await test('every adverse sample raises its expected indicator', async () => {
    const samples = loadSamples().adverse;
    for (let i = 0; i < samples.length; i++) {
      const sample = samples[i];
      const input: ExperimentInput = {
        type: sample.type as ExperimentType,
        text: sample.text,
        secondary: sample.secondary,
        shift: sample.shift,
        iterations: sample.iterations,
        mode: sample.mode
      };
      const result = await runExperiment(input);
      assertEquals(
        result.engine.ruleName,
        sample.expectedIndicator,
        'Adverse sample ' + sample.id + ' raised the wrong indicator.'
      );
    }
  });

  await test('every malformed sample is rejected with its expected code', async () => {
    const samples = loadSamples().malformed;
    for (let i = 0; i < samples.length; i++) {
      const sample = samples[i];
      const text = buildMalformedText(sample);
      const input: ExperimentInput = {
        type: sample.type as ExperimentType,
        text: text,
        secondary: sample.secondary,
        shift: sample.shift,
        iterations: sample.iterations
      };
      await assertRejectsWithCode(
        () => runExperiment(input),
        sample.expectedCode,
        'Malformed sample ' + sample.id + ' was not rejected correctly.'
      );
    }
  });

  /* -------------------------------------------------- recovery */
  group('T-final Safe failure and recovery');

  await test('the engine still works after a rejected submission', async () => {
    try {
      await runExperiment({ type: 'classical-cipher', text: '' });
    } catch (error) {
      // expected
    }
    const result = await runExperiment({ type: 'classical-cipher', text: 'HELLO', shift: 3 });
    assertEquals(result.status, 'completed', 'The engine did not recover after a rejection.');
  });

  await test('repeated identical submissions each produce their own result', async () => {
    const identifiers: string[] = [];
    for (let i = 0; i < 5; i++) {
      const result = await runExperiment({ type: 'classical-cipher', text: 'REPEATED', shift: 4 });
      identifiers.push(result.id);
    }
    for (let i = 0; i < identifiers.length; i++) {
      for (let j = i + 1; j < identifiers.length; j++) {
        assertTrue(identifiers[i] !== identifiers[j], 'Two repeated submissions shared an identifier.');
      }
    }
  });

  await test('state resets cleanly, so a restart reproduces the same behaviour', async () => {
    updatePolicy({ minSafeKdfIterations: 250000 });
    resetPolicy();
    const result = await runExperiment({ type: 'hashing-kdfs', text: 'password', iterations: 120000 });
    assertEquals(result.severity, 'info', 'The policy did not return to its default state.');
  });

  const summary = report('CipherClassroom security engine, unit tests');
  if (summary.failed > 0) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error('The test run could not complete:', error);
  process.exitCode = 1;
});
