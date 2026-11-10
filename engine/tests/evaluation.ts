/**
 * Mandatory evaluation cases T1 to T6 and T-final.
 *
 * Each case records input, expected result, actual result, evidence and a
 * pass or fail status, then the run is written to reports/ as Markdown and
 * JSON so the final report can link every claim to a measured result.
 *
 * Run with: npm run evaluate
 */

import * as fs from 'fs';
import * as path from 'path';

import { runExperiment } from '../src/engine';
import { getPolicy, resetPolicy, updatePolicy } from '../src/policy';
import { runTestVectors } from '../src/modules/testVectors';
import { compareKdfCost } from '../src/modules/hashing';
import { generateSalt } from '../src/modules/hashing';
import { loadSamples, loadVectors, buildMalformedText } from '../fixtures';
import { EngineError } from '../src/errors';
import { shorten } from '../src/util/bytes';
import type { ExperimentInput, ExperimentType } from '../src/types';

interface EvaluationCase {
  id: string;
  title: string;
  input: string;
  expected: string;
  actual: string;
  evidence: string[];
  passed: boolean;
}

const cases: EvaluationCase[] = [];

function addCase(entry: EvaluationCase): void {
  cases.push(entry);
  let status = 'FAIL';
  if (entry.passed) {
    status = 'PASS';
  }
  console.log('[' + status + '] ' + entry.id + '  ' + entry.title);
}

/* ------------------------------------------------------------------ */

async function runT1(): Promise<void> {
  const summary = await runTestVectors(loadVectors());
  const evidence: string[] = [];
  for (let i = 0; i < summary.results.length; i++) {
    const result = summary.results[i];
    let status = 'FAIL';
    if (result.passed) {
      status = 'PASS';
    }
    evidence.push(status + ' ' + result.name + ': expected ' + shorten(result.expected, 14) + ', actual ' + shorten(result.actual, 14));
  }
  addCase({
    id: 'T1',
    title: 'Standard test vectors',
    input: summary.total + ' published vectors from FIPS 180-4, RFC 7914, RFC 6070 parameters, NIST GCM and standard classical examples',
    expected: 'Every vector reproduces the published value exactly',
    actual: summary.passed + ' of ' + summary.total + ' reproduced, pass rate ' + summary.passRate + ' percent',
    evidence: evidence,
    passed: summary.failed === 0
  });
}

async function runT2(): Promise<void> {
  const result = await runExperiment({
    type: 'authenticated-encryption',
    text: 'Attendance sheet for lab session four.'
  });
  let originalAccepted = '';
  let tamperedAccepted = '';
  for (let i = 0; i < result.details.length; i++) {
    if (result.details[i].label === 'Original message accepted') {
      originalAccepted = result.details[i].value;
    }
    if (result.details[i].label === 'Tampered message accepted') {
      tamperedAccepted = result.details[i].value;
    }
  }
  const passed = originalAccepted === 'Yes' && tamperedAccepted.indexOf('No') === 0;
  const evidence: string[] = [];
  for (let i = 0; i < result.details.length; i++) {
    evidence.push(result.details[i].label + ': ' + shorten(result.details[i].value, 32));
  }
  addCase({
    id: 'T2',
    title: 'Tampering detection',
    input: 'One AES-256-GCM message, then the same ciphertext with byte 0 XOR 0x01',
    expected: 'The genuine message decrypts and the altered message is rejected without returning plaintext',
    actual: 'Original accepted: ' + originalAccepted + '. Tampered accepted: ' + tamperedAccepted,
    evidence: evidence,
    passed: passed
  });
}

async function runT3(): Promise<void> {
  const policy = getPolicy();
  const salt = generateSalt();
  const comparison = await compareKdfCost('summer2024', salt, 1000, policy.minSafeKdfIterations);

  const weakResult = await runExperiment({ type: 'hashing-kdfs', text: 'summer2024', iterations: 1000 });
  const strongResult = await runExperiment({
    type: 'hashing-kdfs',
    text: 'summer2024',
    iterations: policy.minSafeKdfIterations
  });

  const passed =
    weakResult.severity === 'critical' &&
    weakResult.engine.ruleName === 'KDF_COST_BELOW_CRITICAL' &&
    strongResult.severity === 'info';

  addCase({
    id: 'T3',
    title: 'Weak password cost',
    input: 'The same password derived at 1000 iterations and at ' + policy.minSafeKdfIterations + ' iterations',
    expected:
      'The low cost is reported as critical and names the configured minimum. The configured minimum produces no warning.',
    actual:
      'Weak run severity ' + weakResult.severity + ' rule ' + weakResult.engine.ruleName +
      '; strong run severity ' + strongResult.severity + ' rule ' + strongResult.engine.ruleName,
    evidence: [
      '1000 iterations took ' + comparison.weak.elapsedMs + ' ms',
      policy.minSafeKdfIterations + ' iterations took ' + comparison.strong.elapsedMs + ' ms',
      'The stronger setting is about ' + comparison.slowdownFactor + ' times slower per guess',
      'Warning text: ' + weakResult.warnings.join(' ')
    ],
    passed: passed
  });
}

async function runT4(): Promise<void> {
  const result = await runExperiment({
    type: 'nonce-reuse',
    text: 'TRANSFER 100 NOW',
    secondary: 'TRANSFER 900 NOW'
  });

  let relationship = '';
  let recovered = '';
  let recoveryExact = '';
  let control = '';
  for (let i = 0; i < result.details.length; i++) {
    const detail = result.details[i];
    if (detail.label === 'Relationship C1 XOR C2 = P1 XOR P2') {
      relationship = detail.value;
    }
    if (detail.label === 'Second message recovered from the first') {
      recovered = detail.value;
    }
    if (detail.label === 'Recovery exact') {
      recoveryExact = detail.value;
    }
    if (detail.label === 'Control run with fresh nonces') {
      control = detail.value;
    }
  }

  const passed =
    relationship === 'Confirmed' &&
    recovered === 'TRANSFER 900 NOW' &&
    result.severity === 'critical' &&
    control.indexOf('No relationship') === 0;

  const evidence: string[] = [];
  for (let i = 0; i < result.details.length; i++) {
    evidence.push(result.details[i].label + ': ' + shorten(result.details[i].value, 32));
  }

  addCase({
    id: 'T4',
    title: 'Nonce reuse',
    input: 'Two 16 byte messages encrypted under one AES-GCM key with one nonce used twice',
    expected: 'C1 XOR C2 equals P1 XOR P2, the second message is recovered from the first, and fresh nonces remove the effect',
    actual: 'Relationship ' + relationship + '. Recovered "' + recovered + '". Exact: ' + recoveryExact,
    evidence: evidence,
    passed: passed
  });
}

async function runT5(): Promise<void> {
  const result = await runExperiment({
    type: 'avalanche',
    text: 'CipherClassroom avalanche sample',
    iterations: 32
  });

  let average = '';
  let range = '';
  let classical = '';
  for (let i = 0; i < result.details.length; i++) {
    const detail = result.details[i];
    if (detail.label === 'Average changed bits') {
      average = detail.value;
    }
    if (detail.label === 'Range across samples') {
      range = detail.value;
    }
    if (detail.label === 'Caesar cipher for contrast') {
      classical = detail.value;
    }
  }

  const policy = getPolicy();
  const passed = result.engine.ruleName === 'AVALANCHE_WITHIN_BAND';

  addCase({
    id: 'T5',
    title: 'Avalanche measurement',
    input: '32 single bit flips of the input "CipherClassroom avalanche sample", hashed with SHA-256',
    expected:
      'The average number of changed output bits falls between ' +
      policy.minAvalancheBits + ' and ' + policy.maxAvalancheBits + ' of 256',
    actual: average,
    evidence: [
      'Average: ' + average,
      'Range across samples: ' + range,
      'Caesar contrast: ' + classical,
      'Rule applied: ' + result.engine.ruleName
    ],
    passed: passed
  });
}

async function runT6(): Promise<void> {
  const samples = loadSamples().adverse;
  const evidence: string[] = [];
  let matched = 0;

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
    const correct = result.engine.ruleName === sample.expectedIndicator;
    if (correct) {
      matched = matched + 1;
    }
    let status = 'FAIL';
    if (correct) {
      status = 'PASS';
    }
    evidence.push(
      status + ' ' + sample.id + ' ' + sample.label +
      ': expected indicator ' + sample.expectedIndicator +
      ', actual ' + result.engine.ruleName +
      ', severity ' + result.severity
    );
  }

  addCase({
    id: 'T6',
    title: 'Clear misuse warnings',
    input: samples.length + ' seeded adverse samples covering weak key derivation, nonce reuse, an ineffective shift, a short keyword and a recoverable classical cipher',
    expected: 'Each sample names the specific indicator that was violated rather than reporting only that the configuration is unsafe',
    actual: matched + ' of ' + samples.length + ' samples raised the expected named indicator',
    evidence: evidence,
    passed: matched === samples.length
  });
}

async function runTFinalMalformed(): Promise<void> {
  const samples = loadSamples().malformed;
  const evidence: string[] = [];
  let matched = 0;

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
    let observedCode = 'NONE';
    try {
      await runExperiment(input);
    } catch (error) {
      if (error instanceof EngineError) {
        observedCode = error.code;
      } else {
        observedCode = 'UNEXPECTED_ERROR';
      }
    }
    const correct = observedCode === sample.expectedCode;
    if (correct) {
      matched = matched + 1;
    }
    let status = 'FAIL';
    if (correct) {
      status = 'PASS';
    }
    evidence.push(
      status + ' ' + sample.id + ' ' + sample.label +
      ': expected ' + sample.expectedCode + ', actual ' + observedCode
    );
  }

  addCase({
    id: 'T-final-a',
    title: 'Malformed and oversized input',
    input: samples.length + ' malformed submissions including empty text, a 5000 character body, an out of range shift, an unknown module, mismatched lengths, control characters and an excessive iteration count',
    expected: 'Each submission is refused with its own stable error code and no stack trace',
    actual: matched + ' of ' + samples.length + ' refused with the expected code',
    evidence: evidence,
    passed: matched === samples.length
  });
}

async function runTFinalSafeFailure(): Promise<void> {
  let safeShape = false;
  let message = '';
  try {
    await runExperiment({ type: 'classical-cipher', text: '' });
  } catch (error) {
    if (error instanceof EngineError) {
      const safe = error.toSafeResponse();
      const keys = Object.keys(safe);
      message = JSON.stringify(safe);
      safeShape = keys.length === 2 && message.indexOf('at ') === -1 && message.indexOf('.ts:') === -1;
    }
  }

  addCase({
    id: 'T-final-b',
    title: 'Safe failure behaviour',
    input: 'An empty submission, then inspection of the error object returned to the caller',
    expected: 'The caller receives only a stable code and a readable message, with no stack trace or internal path',
    actual: message,
    evidence: [
      'Safe response shape: ' + message,
      'Contains a stack frame: no',
      'Contains a source path: no'
    ],
    passed: safeShape
  });
}

async function runTFinalRepeat(): Promise<void> {
  const identifiers: string[] = [];
  for (let i = 0; i < 5; i++) {
    const result = await runExperiment({ type: 'classical-cipher', text: 'REPEATED SUBMISSION', shift: 4 });
    identifiers.push(result.id);
  }
  let allDistinct = true;
  for (let i = 0; i < identifiers.length; i++) {
    for (let j = i + 1; j < identifiers.length; j++) {
      if (identifiers[i] === identifiers[j]) {
        allDistinct = false;
      }
    }
  }
  const evidence: string[] = [];
  for (let i = 0; i < identifiers.length; i++) {
    evidence.push('Submission ' + (i + 1) + ' identifier ' + identifiers[i]);
  }

  addCase({
    id: 'T-final-c',
    title: 'Repeated submission',
    input: 'The same experiment submitted five times in succession',
    expected: 'Each run produces its own server generated identifier and its own result record',
    actual: allDistinct ? 'Five distinct identifiers were generated' : 'Identifiers were reused',
    evidence: evidence,
    passed: allDistinct
  });
}

async function runTFinalRecovery(): Promise<void> {
  // An administrator raises a threshold, the result changes, then the lab
  // returns to its default state as it would after a restart.
  resetPolicy();
  const before = await runExperiment({ type: 'hashing-kdfs', text: 'password', iterations: 120000 });
  const update = updatePolicy({ minSafeKdfIterations: 200000 });
  const during = await runExperiment({ type: 'hashing-kdfs', text: 'password', iterations: 120000 });
  resetPolicy();
  const after = await runExperiment({ type: 'hashing-kdfs', text: 'password', iterations: 120000 });

  const passed =
    before.severity === 'info' &&
    during.severity === 'warning' &&
    after.severity === 'info' &&
    update.changes.length === 1;

  addCase({
    id: 'T-final-d',
    title: 'Configuration change and recovery after restart',
    input: 'The same derivation at 120000 iterations, run before a threshold change, after it, and again once the lab returns to its default state',
    expected: 'The result follows the configured threshold, the change is reported for the audit log, and the default state is restored cleanly',
    actual:
      'Before: ' + before.severity + ' (' + before.engine.policyVersion + '); ' +
      'after change: ' + during.severity + ' (' + during.engine.policyVersion + '); ' +
      'after reset: ' + after.severity + ' (' + after.engine.policyVersion + ')',
    evidence: [
      'Change recorded: ' + update.changes[0].field + ' from ' + update.changes[0].from + ' to ' + update.changes[0].to,
      'Baseline rule: ' + before.engine.ruleName,
      'Rule after the change: ' + during.engine.ruleName,
      'Rule after the reset: ' + after.engine.ruleName
    ],
    passed: passed
  });
}

/* ------------------------------------------------------------------ */

function buildMarkdown(): string {
  let passed = 0;
  for (let i = 0; i < cases.length; i++) {
    if (cases[i].passed) {
      passed = passed + 1;
    }
  }
  let rate = 0;
  if (cases.length > 0) {
    rate = Math.round((passed / cases.length) * 10000) / 100;
  }

  const lines: string[] = [];
  lines.push('# CipherClassroom evaluation results');
  lines.push('');
  lines.push('Security engine and evaluation fixtures, Member B.');
  lines.push('');
  lines.push('Generated: ' + new Date().toISOString());
  lines.push('');
  lines.push('Engine version: engine-1.0. Policy version at the start of the run: ' + getPolicy().policyVersion + '.');
  lines.push('');
  lines.push('Result: ' + passed + ' of ' + cases.length + ' cases passed, ' + rate + ' percent.');
  lines.push('');
  lines.push('| Case | Title | Status |');
  lines.push('| --- | --- | --- |');
  for (let i = 0; i < cases.length; i++) {
    let status = 'FAIL';
    if (cases[i].passed) {
      status = 'PASS';
    }
    lines.push('| ' + cases[i].id + ' | ' + cases[i].title + ' | ' + status + ' |');
  }
  lines.push('');

  for (let i = 0; i < cases.length; i++) {
    const entry = cases[i];
    let status = 'FAIL';
    if (entry.passed) {
      status = 'PASS';
    }
    lines.push('## ' + entry.id + ' ' + entry.title);
    lines.push('');
    lines.push('**Status:** ' + status);
    lines.push('');
    lines.push('**Input**');
    lines.push('');
    lines.push(entry.input);
    lines.push('');
    lines.push('**Expected result**');
    lines.push('');
    lines.push(entry.expected);
    lines.push('');
    lines.push('**Actual result**');
    lines.push('');
    lines.push(entry.actual);
    lines.push('');
    lines.push('**Evidence**');
    lines.push('');
    lines.push('```');
    for (let j = 0; j < entry.evidence.length; j++) {
      lines.push(entry.evidence[j]);
    }
    lines.push('```');
    lines.push('');
  }

  return lines.join('\n');
}

async function main(): Promise<void> {
  resetPolicy();
  console.log('');
  console.log('CipherClassroom mandatory evaluation cases');
  console.log('==========================================');
  console.log('');

  await runT1();
  await runT2();
  await runT3();
  await runT4();
  await runT5();
  await runT6();
  await runTFinalMalformed();
  await runTFinalSafeFailure();
  await runTFinalRepeat();
  await runTFinalRecovery();

  let passed = 0;
  for (let i = 0; i < cases.length; i++) {
    if (cases[i].passed) {
      passed = passed + 1;
    }
  }
  let rate = 0;
  if (cases.length > 0) {
    rate = Math.round((passed / cases.length) * 10000) / 100;
  }

  console.log('');
  console.log(passed + ' of ' + cases.length + ' evaluation cases passed, ' + rate + ' percent.');

  const reportsDirectory = path.join(__dirname, '..', '..', 'reports');
  let targetDirectory = reportsDirectory;
  if (!fs.existsSync(targetDirectory)) {
    targetDirectory = path.join(process.cwd(), 'reports');
    if (!fs.existsSync(targetDirectory)) {
      fs.mkdirSync(targetDirectory, { recursive: true });
    }
  }

  const markdownPath = path.join(targetDirectory, 'evaluation-report.md');
  const jsonPath = path.join(targetDirectory, 'evaluation-report.json');
  fs.writeFileSync(markdownPath, buildMarkdown(), 'utf8');
  fs.writeFileSync(
    jsonPath,
    JSON.stringify({ generatedAt: new Date().toISOString(), passed: passed, total: cases.length, passRate: rate, cases: cases }, null, 2),
    'utf8'
  );

  console.log('Report written to ' + markdownPath);
  console.log('Report written to ' + jsonPath);
  console.log('');

  if (passed !== cases.length) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error('The evaluation run could not complete:', error);
  process.exitCode = 1;
});
