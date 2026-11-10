/**
 * The security engine.
 *
 * Every module below is an independently testable function. This file is
 * the single entry point the API layer calls. It validates input, runs the
 * selected module, attaches explainable evidence and reproducibility
 * metadata, and offers an audit event to the caller.
 *
 * The engine never stores anything and never writes to the network.
 */

import {
  caesarDecrypt,
  caesarEncrypt,
  frequencyBreak,
  indexOfCoincidence,
  vigenereDecrypt,
  vigenereEncrypt
} from './modules/classical';
import { generateKeyBytes, generateNonce, runTamperCheck } from './modules/aead';
import {
  assessKdfCost,
  compareKdfCost,
  deriveKeyPbkdf2,
  generateSalt,
  sha256HexText
} from './modules/hashing';
import { compareWithFreshNonces, demonstrateNonceReuse } from './modules/nonceReuse';
import { measureAvalanche, measureClassicalAvalanche } from './modules/avalanche';
import { runTestVectors } from './modules/testVectors';
import { loadVectors } from '../fixtures';
import { EngineError } from './errors';
import { getPolicy, type LabPolicy } from './policy';
import { shorten, toHex, utf8Encode } from './util/bytes';
import {
  normalizeText,
  validateIterations,
  validateKeyword,
  validateShift,
  validateText,
  validateType
} from './util/validate';
import type {
  AuditEventDraft,
  DetailItem,
  EngineOptions,
  EngineResult,
  EvidenceItem,
  ExperimentInput,
  ExperimentType,
  Severity
} from './types';

export const ENGINE_VERSION = 'engine-1.0';

interface ResultDraft {
  type: ExperimentType;
  title: string;
  severity: Severity;
  summary: string;
  details: DetailItem[];
  warnings: string[];
  evidence: EvidenceItem[];
  ruleName: string;
  algorithm: string;
  reasons: string[];
  thresholds: Record<string, string>;
}

function newIdentifier(): string {
  const globalObject = globalThis as unknown as { crypto?: Crypto };
  if (globalObject.crypto !== undefined && typeof globalObject.crypto.randomUUID === 'function') {
    return globalObject.crypto.randomUUID();
  }
  const nodeCrypto = require('node:crypto') as { webcrypto: Crypto };
  return nodeCrypto.webcrypto.randomUUID();
}

function finish(draft: ResultDraft, startedAt: number, inputDigest: string, policy: LabPolicy): EngineResult {
  const elapsed = Math.round((Date.now() - startedAt) * 100) / 100;
  return {
    id: newIdentifier(),
    type: draft.type,
    title: draft.title,
    timestamp: new Date().toISOString(),
    status: 'completed',
    severity: draft.severity,
    summary: draft.summary,
    details: draft.details,
    warnings: draft.warnings,
    evidence: draft.evidence,
    durationMs: elapsed,
    version: ENGINE_VERSION,
    engine: {
      ruleName: draft.ruleName,
      engineVersion: ENGINE_VERSION,
      policyVersion: policy.policyVersion,
      algorithm: draft.algorithm,
      thresholds: draft.thresholds,
      reasons: draft.reasons,
      inputDigest: inputDigest
    }
  };
}

function emit(options: EngineOptions | undefined, event: AuditEventDraft): void {
  if (options !== undefined && options.onAuditEvent !== undefined) {
    options.onAuditEvent(event);
  }
}

/**
 * Runs one experiment.
 *
 * Throws EngineError on invalid input. The caller converts that into a safe
 * `{ code, message }` response. Nothing in the thrown message exposes
 * internal paths or stack traces.
 */
export async function runExperiment(input: ExperimentInput, options?: EngineOptions): Promise<EngineResult> {
  const policy = getPolicy();
  const startedAt = Date.now();
  const type = validateType(input.type);

  let actor = 'unknown';
  if (options !== undefined && options.actor !== undefined) {
    actor = options.actor;
  }

  let inputDigest = '';
  try {
    const primaryText = validateText(input.text, policy, 'Input text');
    const fullDigest = await sha256HexText(primaryText);
    inputDigest = fullDigest.substring(0, 16);

    let draft: ResultDraft;
    if (type === 'classical-cipher') {
      draft = await runClassical(input, primaryText, policy);
    } else if (type === 'authenticated-encryption') {
      draft = await runAuthenticatedEncryption(primaryText);
    } else if (type === 'hashing-kdfs') {
      draft = await runHashing(input, primaryText, policy);
    } else if (type === 'nonce-reuse') {
      draft = await runNonceReuse(input, primaryText, policy);
    } else if (type === 'test-vectors') {
      draft = await runVectors();
    } else {
      draft = await runAvalanche(input, primaryText, policy);
    }

    const result = finish(draft, startedAt, inputDigest, policy);
    emit(options, {
      timestamp: result.timestamp,
      action: 'experiment.run',
      outcome: 'success',
      severity: result.severity,
      detail: actor + ' ran the ' + result.title + ' module, rule ' + draft.ruleName + '.',
      resultId: result.id,
      inputDigest: inputDigest
    });
    return result;
  } catch (error) {
    let code = 'INVALID_INPUT';
    let message = 'The request could not be processed.';
    if (error instanceof EngineError) {
      code = error.code;
      message = error.message;
    }
    emit(options, {
      timestamp: new Date().toISOString(),
      action: 'experiment.rejected',
      outcome: 'failure',
      severity: 'warning',
      detail: actor + ' submitted input that was rejected with code ' + code + '.',
      resultId: null,
      inputDigest: inputDigest
    });
    if (error instanceof EngineError) {
      throw error;
    }
    throw new EngineError('INVALID_INPUT', message);
  }
}

/* ------------------------------------------------------------------ */
/* FR-2 Classical cipher                                               */
/* ------------------------------------------------------------------ */

async function runClassical(input: ExperimentInput, text: string, policy: LabPolicy): Promise<ResultDraft> {
  let mode = 'caesar';
  if (input.mode !== undefined && input.mode !== '') {
    mode = input.mode;
  }

  const thresholds: Record<string, string> = {
    ineffectiveCaesarShifts: policy.ineffectiveCaesarShifts.join(', '),
    minVigenereKeywordLength: String(policy.minVigenereKeywordLength)
  };

  if (mode === 'break') {
    const broken = frequencyBreak(text);
    const topThree: string[] = [];
    for (let i = 0; i < 3 && i < broken.rankedShifts.length; i++) {
      topThree.push('shift ' + broken.rankedShifts[i].shift + ' scored ' + broken.rankedShifts[i].score);
    }
    return {
      type: 'classical-cipher',
      title: 'Classical cipher broken by frequency analysis',
      severity: 'critical',
      summary:
        'The shift was recovered without the key. Letter frequency analysis identified shift ' +
        broken.recoveredShift +
        ' from ' +
        broken.totalLetters +
        ' letters of ciphertext.',
      details: [
        { label: 'Recovered shift', value: String(broken.recoveredShift) },
        { label: 'Recovered plaintext', value: broken.recoveredPlaintext },
        { label: 'Best three candidates', value: topThree.join('; ') },
        { label: 'Index of coincidence', value: String(indexOfCoincidence(text)) }
      ],
      warnings: [
        'A Caesar cipher has only 26 possible keys and preserves letter frequencies, so the key is recoverable from the ciphertext alone.'
      ],
      evidence: [
        { name: 'Method', value: 'Chi squared comparison against English letter frequencies, all 26 shifts' },
        { name: 'Letters analysed', value: String(broken.totalLetters) },
        { name: 'Key material used', value: 'None. The attack had no access to the key.' }
      ],
      ruleName: 'CLASSICAL_CIPHER_BROKEN_WITHOUT_KEY',
      algorithm: 'Caesar with chi squared frequency analysis',
      reasons: ['Recovered shift ' + broken.recoveredShift + ' using ciphertext only'],
      thresholds: thresholds
    };
  }

  if (mode === 'vigenere') {
    const keyword = validateKeyword(input.secondary);
    const ciphertext = vigenereEncrypt(text, keyword);
    const roundTrip = vigenereDecrypt(ciphertext, keyword);
    const warnings: string[] = [
      'Vigenere is a classical cipher. It resists a single frequency count but falls to Kasiski examination once enough ciphertext is available.'
    ];
    const reasons: string[] = [];
    let severity: Severity = 'warning';
    if (keyword.length < policy.minVigenereKeywordLength) {
      severity = 'critical';
      warnings.push(
        'The keyword is ' +
          keyword.length +
          ' characters, below the configured minimum of ' +
          policy.minVigenereKeywordLength +
          '. A short keyword reduces the cipher to a small set of interleaved Caesar shifts.'
      );
      reasons.push('keyword length ' + keyword.length + ' < minVigenereKeywordLength');
    } else {
      reasons.push('keyword length ' + keyword.length + ' meets the configured minimum');
    }
    return {
      type: 'classical-cipher',
      title: 'Classical cipher, Vigenere',
      severity: severity,
      summary: 'Vigenere encryption applied with a keyword of ' + keyword.length + ' characters.',
      details: [
        { label: 'Ciphertext', value: ciphertext },
        { label: 'Decrypted for verification', value: roundTrip },
        { label: 'Keyword length', value: String(keyword.length) },
        { label: 'Index of coincidence of ciphertext', value: String(indexOfCoincidence(ciphertext)) }
      ],
      warnings: warnings,
      evidence: [
        { name: 'Algorithm', value: 'Vigenere polyalphabetic substitution' },
        { name: 'Round trip', value: roundTrip === text ? 'Decryption returned the original text' : 'Mismatch' },
        { name: 'Keyword stored', value: 'No. The keyword is used in memory and never recorded.' }
      ],
      ruleName: severity === 'critical' ? 'VIGENERE_KEYWORD_TOO_SHORT' : 'VIGENERE_APPLIED',
      algorithm: 'Vigenere',
      reasons: reasons,
      thresholds: thresholds
    };
  }

  const shift = validateShift(input.shift);
  const ciphertext = caesarEncrypt(text, shift);
  const roundTrip = caesarDecrypt(ciphertext, shift);
  const classicalAvalanche = measureClassicalAvalanche(text, shift);

  let ineffective = false;
  for (let i = 0; i < policy.ineffectiveCaesarShifts.length; i++) {
    if (policy.ineffectiveCaesarShifts[i] === shift) {
      ineffective = true;
      break;
    }
  }

  const warnings: string[] = [];
  const reasons: string[] = [];
  let severity: Severity = 'warning';
  if (ineffective) {
    severity = 'critical';
    warnings.push(
      'A shift of ' + shift + ' leaves the text unchanged, so no confidentiality is applied at all.'
    );
    reasons.push('shift ' + shift + ' is listed in ineffectiveCaesarShifts');
  } else {
    warnings.push(
      'The Caesar cipher has 26 possible keys and can be broken by trying every one, so it offers no modern confidentiality.'
    );
    reasons.push('shift ' + shift + ' applied, key space is 26');
  }

  return {
    type: 'classical-cipher',
    title: 'Classical cipher, Caesar',
    severity: severity,
    summary: ineffective
      ? 'The configured shift performs no encryption. The output is identical to the input.'
      : 'Caesar encryption applied with shift ' + shift + '. The key space is 26, so exhaustive search is immediate.',
    details: [
      { label: 'Ciphertext', value: ciphertext },
      { label: 'Decrypted for verification', value: roundTrip },
      { label: 'Shift', value: String(shift) },
      {
        label: 'Diffusion',
        value:
          classicalAvalanche.changedCharacters +
          ' of ' +
          classicalAvalanche.total +
          ' output characters change when one input character changes'
      }
    ],
    warnings: warnings,
    evidence: [
      { name: 'Algorithm', value: 'Caesar alphabetic rotation' },
      { name: 'Key space', value: '26 possible keys' },
      { name: 'Round trip', value: roundTrip === text ? 'Decryption returned the original text' : 'Mismatch' },
      { name: 'Validation applied', value: 'Shift restricted to the range 0 to 25 on the server' }
    ],
    ruleName: ineffective ? 'CAESAR_SHIFT_INEFFECTIVE' : 'CAESAR_APPLIED',
    algorithm: 'Caesar',
    reasons: reasons,
    thresholds: thresholds
  };
}

/* ------------------------------------------------------------------ */
/* FR-3 Authenticated encryption                                       */
/* ------------------------------------------------------------------ */

async function runAuthenticatedEncryption(text: string): Promise<ResultDraft> {
  const keyBytes = await generateKeyBytes();
  const nonce = generateNonce();
  const report = await runTamperCheck(keyBytes, nonce, text, 0);

  const passed = report.originalAccepted && !report.tamperedAccepted;
  const warnings: string[] = [];
  const reasons: string[] = [];
  if (passed) {
    reasons.push('original ciphertext accepted and tampered ciphertext rejected');
  } else {
    warnings.push('The integrity check did not behave as expected and this result needs review.');
    reasons.push('tamper check did not produce the expected outcome');
  }

  return {
    type: 'authenticated-encryption',
    title: 'Authenticated encryption',
    severity: passed ? 'info' : 'critical',
    summary: passed
      ? 'AES-256-GCM returned the original message and rejected a ciphertext altered by a single bit.'
      : 'The authenticated encryption check did not behave as expected.',
    details: [
      { label: 'Ciphertext with tag, hex', value: toHex(report.ciphertext) },
      { label: 'Tampered ciphertext, hex', value: toHex(report.tampered) },
      { label: 'Original message accepted', value: report.originalAccepted ? 'Yes' : 'No' },
      { label: 'Tampered message accepted', value: report.tamperedAccepted ? 'Yes, which is a failure' : 'No, rejected as expected' },
      { label: 'Rejection reason', value: report.reason }
    ],
    warnings: warnings,
    evidence: [
      { name: 'Algorithm', value: 'AES-256-GCM, 96 bit nonce, 128 bit authentication tag' },
      { name: 'Nonce', value: 'Freshly generated for this run, hex ' + shorten(toHex(nonce), 8) },
      { name: 'Tampering applied', value: 'Byte 0 of the ciphertext XOR 0x01' },
      { name: 'Key handling', value: 'Generated in memory for this run, never logged or returned' }
    ],
    ruleName: passed ? 'AEAD_INTEGRITY_VERIFIED' : 'AEAD_INTEGRITY_UNEXPECTED',
    algorithm: 'AES-256-GCM',
    reasons: reasons,
    thresholds: { tagLengthBits: '128', nonceLengthBits: '96' }
  };
}

/* ------------------------------------------------------------------ */
/* FR-4 Hashing and KDFs                                               */
/* ------------------------------------------------------------------ */

async function runHashing(input: ExperimentInput, text: string, policy: LabPolicy): Promise<ResultDraft> {
  const iterations = validateIterations(input.iterations, policy);
  const salt = generateSalt();
  const outcome = await deriveKeyPbkdf2(text, salt, iterations);
  const assessment = assessKdfCost(outcome, policy);
  const digestHex = await sha256HexText(text);

  const details: DetailItem[] = [
    { label: 'SHA-256 digest of the input', value: digestHex },
    { label: 'PBKDF2 derived key, hex', value: toHex(outcome.derivedKey) },
    { label: 'Salt, hex', value: outcome.saltHex },
    { label: 'Iterations', value: String(iterations) },
    { label: 'Time for one derivation', value: outcome.elapsedMs + ' ms' },
    {
      label: 'Guesses per second at this cost',
      value: 'about ' + assessment.estimatedGuessesPerSecond + ' per second on this machine, single threaded'
    }
  ];

  return {
    type: 'hashing-kdfs',
    title: 'Hashing and key derivation',
    severity: assessment.severity,
    summary:
      'SHA-256 produced a deterministic digest. PBKDF2-HMAC-SHA-256 derived a salted key in ' +
      outcome.elapsedMs +
      ' ms at ' +
      iterations +
      ' iterations.',
    details: details,
    warnings: assessment.warnings,
    evidence: [
      { name: 'Algorithms', value: 'SHA-256 and PBKDF2-HMAC-SHA-256' },
      { name: 'Salt', value: '128 bit salt generated fresh for this derivation' },
      { name: 'Configured minimum iterations', value: String(policy.minSafeKdfIterations) },
      { name: 'Configured critical threshold', value: String(policy.criticalKdfIterations) },
      { name: 'Input handling', value: 'The supplied password is never stored or logged. Only a 16 character digest prefix is recorded.' }
    ],
    ruleName:
      assessment.severity === 'critical'
        ? 'KDF_COST_BELOW_CRITICAL'
        : assessment.severity === 'warning'
          ? 'KDF_COST_BELOW_MINIMUM'
          : 'KDF_COST_ACCEPTABLE',
    algorithm: 'PBKDF2-HMAC-SHA-256',
    reasons: assessment.reasons,
    thresholds: {
      criticalKdfIterations: String(policy.criticalKdfIterations),
      minSafeKdfIterations: String(policy.minSafeKdfIterations),
      maxKdfIterations: String(policy.maxKdfIterations)
    }
  };
}

/* ------------------------------------------------------------------ */
/* FR-5 Nonce reuse                                                    */
/* ------------------------------------------------------------------ */

async function runNonceReuse(input: ExperimentInput, text: string, policy: LabPolicy): Promise<ResultDraft> {
  if (input.secondary === undefined) {
    throw new EngineError('INVALID_INPUT', 'A second message is required for the nonce reuse demonstration.');
  }
  const second = validateText(input.secondary, policy, 'Second message');
  const firstLength = utf8Encode(text).length;
  const secondLength = utf8Encode(second).length;
  if (firstLength !== secondLength) {
    throw new EngineError(
      'LENGTH_MISMATCH',
      'Both messages must be the same length in bytes. The first is ' +
        firstLength +
        ' bytes and the second is ' +
        secondLength +
        ' bytes.'
    );
  }

  const evidence = await demonstrateNonceReuse(text, second);
  const control = await compareWithFreshNonces(text, second);

  const reasons: string[] = [];
  if (evidence.relationshipHolds) {
    reasons.push('C1 XOR C2 equalled P1 XOR P2, confirming one shared keystream');
  }
  if (evidence.recoveryExact) {
    reasons.push('the second plaintext was recovered byte for byte from the first');
  }
  if (!control.relationshipHolds) {
    reasons.push('the same comparison with fresh nonces produced no relationship, isolating nonce reuse as the cause');
  }

  return {
    type: 'nonce-reuse',
    title: 'Nonce reuse demonstration',
    severity: 'critical',
    summary:
      'Reusing one AES-GCM nonce under one key reproduced the same keystream twice. The second message was recovered from the first without the key.',
    details: [
      { label: 'First ciphertext without tag, hex', value: evidence.firstCiphertextHex },
      { label: 'Second ciphertext without tag, hex', value: evidence.secondCiphertextHex },
      { label: 'Ciphertext XOR', value: evidence.ciphertextXorHex },
      { label: 'Plaintext XOR', value: evidence.plaintextXorHex },
      { label: 'Relationship C1 XOR C2 = P1 XOR P2', value: evidence.relationshipHolds ? 'Confirmed' : 'Not observed' },
      { label: 'Second message recovered from the first', value: evidence.recoveredSecondMessage },
      { label: 'Recovery exact', value: evidence.recoveryExact ? 'Yes, byte for byte' : 'No' },
      {
        label: 'Control run with fresh nonces',
        value: control.relationshipHolds
          ? 'Relationship still present, which is unexpected'
          : 'No relationship, so the leak is caused by the reused nonce'
      }
    ],
    warnings: [
      'Never reuse a nonce with the same AES-GCM key. This module demonstrates an unsafe construction on purpose, in isolation, with a key generated locally for the run.'
    ],
    evidence: [
      { name: 'Scope', value: 'In memory demonstration. The key and nonce are generated for this run and discarded.' },
      { name: 'Nonce used twice, hex', value: evidence.nonceHex },
      { name: 'Message length', value: evidence.messageLengthBytes + ' bytes each' },
      { name: 'Observed relationship', value: 'C1 XOR C2 = P1 XOR P2 across the ciphertext body' },
      { name: 'Control', value: 'Identical messages encrypted with fresh nonces show no such relationship' }
    ],
    ruleName: 'NONCE_REUSED_UNDER_SAME_KEY',
    algorithm: 'AES-256-GCM with a deliberately repeated nonce',
    reasons: reasons,
    thresholds: { nonceLengthBits: '96', reuseTolerance: '0' }
  };
}

/* ------------------------------------------------------------------ */
/* FR-6 Test vectors                                                   */
/* ------------------------------------------------------------------ */

async function runVectors(): Promise<ResultDraft> {
  const summary = await runTestVectors(loadVectors());
  const details: DetailItem[] = [];
  for (let i = 0; i < summary.results.length; i++) {
    const result = summary.results[i];
    let status = 'FAIL';
    if (result.passed) {
      status = 'PASS';
    }
    details.push({
      label: status + ' ' + result.name,
      value: 'expected ' + shorten(result.expected, 16) + ' | actual ' + shorten(result.actual, 16)
    });
  }

  const warnings: string[] = [];
  if (summary.failed > 0) {
    warnings.push(summary.failed + ' published test vector(s) did not reproduce. The implementation must not be trusted until this is resolved.');
  }

  return {
    type: 'test-vectors',
    title: 'Test vector checker',
    severity: summary.failed === 0 ? 'info' : 'critical',
    summary: summary.passed + ' of ' + summary.total + ' published test vectors reproduced exactly.',
    details: details,
    warnings: warnings,
    evidence: [
      { name: 'Sources', value: 'FIPS 180-4, RFC 7914, RFC 6070 parameters, NIST GCM specification, standard classical worked examples' },
      { name: 'Vectors run', value: String(summary.total) },
      { name: 'Pass rate', value: summary.passRate + ' percent' },
      { name: 'Determinism', value: 'All vectors use fixed keys, salts and nonces, so every run produces the same result' }
    ],
    ruleName: summary.failed === 0 ? 'VECTORS_ALL_REPRODUCED' : 'VECTORS_MISMATCH',
    algorithm: 'Published vector comparison',
    reasons: [summary.passed + ' passed', summary.failed + ' failed'],
    thresholds: { requiredPassRate: '100' }
  };
}

/* ------------------------------------------------------------------ */
/* Avalanche                                                           */
/* ------------------------------------------------------------------ */

async function runAvalanche(input: ExperimentInput, text: string, policy: LabPolicy): Promise<ResultDraft> {
  let sampleCount = 32;
  if (input.iterations !== undefined && Number.isInteger(input.iterations)) {
    if (input.iterations < 1 || input.iterations > 256) {
      throw new EngineError('INVALID_PARAMETER', 'The avalanche sample count must be between 1 and 256.');
    }
    sampleCount = input.iterations;
  }

  const report = await measureAvalanche(text, sampleCount, policy);
  const classical = measureClassicalAvalanche(text, 3);

  const warnings: string[] = [];
  const reasons: string[] = [];
  if (report.withinPolicyBand) {
    reasons.push(
      'average of ' + report.averageChangedBits + ' bits falls inside the configured band of ' +
        report.bandLow + ' to ' + report.bandHigh
    );
  } else {
    warnings.push(
      'The average of ' +
        report.averageChangedBits +
        ' changed bits falls outside the configured band of ' +
        report.bandLow +
        ' to ' +
        report.bandHigh +
        '.'
    );
    reasons.push('average outside the configured band');
  }

  const firstSample = report.samples[0];

  return {
    type: 'avalanche',
    title: 'Avalanche measurement',
    severity: report.withinPolicyBand ? 'info' : 'warning',
    summary:
      'Flipping one input bit changed ' +
      report.averageChangedBits +
      ' of 256 SHA-256 output bits on average across ' +
      report.samples.length +
      ' measurements.',
    details: [
      { label: 'Original SHA-256', value: firstSample.originalDigestHex },
      { label: 'SHA-256 after flipping bit 0', value: firstSample.mutatedDigestHex },
      { label: 'Average changed bits', value: report.averageChangedBits + ' of 256 (' + report.averagePercent + ' percent)' },
      { label: 'Range across samples', value: report.minimumChangedBits + ' to ' + report.maximumChangedBits + ' bits' },
      { label: 'Samples taken', value: String(report.samples.length) },
      {
        label: 'Caesar cipher for contrast',
        value:
          classical.changedCharacters +
          ' of ' +
          classical.total +
          ' output characters change when one input character changes'
      }
    ],
    warnings: warnings,
    evidence: [
      { name: 'Measurement', value: 'Hamming distance in bits between digests of inputs differing by one bit' },
      { name: 'Expected value', value: 'About 128 of 256 bits for a hash that behaves like a random function' },
      { name: 'Configured band', value: report.bandLow + ' to ' + report.bandHigh + ' bits' },
      { name: 'Sampling', value: 'Each of the first ' + report.samples.length + ' input bits flipped in turn, then averaged' }
    ],
    ruleName: report.withinPolicyBand ? 'AVALANCHE_WITHIN_BAND' : 'AVALANCHE_OUTSIDE_BAND',
    algorithm: 'SHA-256',
    reasons: reasons,
    thresholds: {
      minAvalancheBits: String(policy.minAvalancheBits),
      maxAvalancheBits: String(policy.maxAvalancheBits)
    }
  };
}

/* ------------------------------------------------------------------ */
/* FR-1 Guided experiments                                             */
/* ------------------------------------------------------------------ */

export interface GuidedStep {
  step: number;
  module: ExperimentType;
  result: EngineResult;
}

/**
 * FR-1. Runs the modules in the order the specification sets out, passing
 * only validated and normalized data from one stage to the next. Each stage
 * returns its own explainable result with evidence attached.
 */
export async function runGuidedSequence(sampleText: string, options?: EngineOptions): Promise<GuidedStep[]> {
  const policy = getPolicy();
  const normalized = normalizeText(sampleText);
  const steps: GuidedStep[] = [];

  const plan: ExperimentInput[] = [
    { type: 'classical-cipher', text: normalized, shift: 3, mode: 'caesar' },
    { type: 'authenticated-encryption', text: normalized },
    { type: 'hashing-kdfs', text: normalized, iterations: policy.minSafeKdfIterations },
    { type: 'nonce-reuse', text: 'TRANSFER 100 NOW', secondary: 'TRANSFER 900 NOW' },
    { type: 'test-vectors', text: normalized },
    { type: 'avalanche', text: normalized, iterations: 16 }
  ];

  for (let i = 0; i < plan.length; i++) {
    const result = await runExperiment(plan[i], options);
    steps.push({ step: i + 1, module: plan[i].type, result: result });
  }

  return steps;
}

/** Summary used by the reports module, FR-7. */
export interface SequenceSummary {
  totalSteps: number;
  criticalFindings: number;
  warningFindings: number;
  informationalFindings: number;
  totalDurationMs: number;
  ruleNames: string[];
}

export function summariseSequence(steps: GuidedStep[]): SequenceSummary {
  let critical = 0;
  let warning = 0;
  let informational = 0;
  let duration = 0;
  const ruleNames: string[] = [];

  for (let i = 0; i < steps.length; i++) {
    const result = steps[i].result;
    if (result.severity === 'critical') {
      critical = critical + 1;
    } else if (result.severity === 'warning') {
      warning = warning + 1;
    } else {
      informational = informational + 1;
    }
    duration = duration + result.durationMs;
    ruleNames.push(result.engine.ruleName);
  }

  return {
    totalSteps: steps.length,
    criticalFindings: critical,
    warningFindings: warning,
    informationalFindings: informational,
    totalDurationMs: Math.round(duration * 100) / 100,
    ruleNames: ruleNames
  };
}

export { compareKdfCost };
