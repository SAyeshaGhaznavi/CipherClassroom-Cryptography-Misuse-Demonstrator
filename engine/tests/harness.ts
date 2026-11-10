/**
 * A very small test harness.
 *
 * The project has no test framework dependency on purpose. Everything runs
 * from a plain Node process so the lab starts on an ordinary laptop with
 * nothing installed beyond TypeScript.
 */

export interface CaseRecord {
  group: string;
  name: string;
  passed: boolean;
  message: string;
  durationMs: number;
}

const records: CaseRecord[] = [];
let currentGroup = 'general';

export function group(name: string): void {
  currentGroup = name;
}

export async function test(name: string, body: () => void | Promise<void>): Promise<void> {
  const startedAt = Date.now();
  try {
    await body();
    records.push({
      group: currentGroup,
      name: name,
      passed: true,
      message: 'ok',
      durationMs: Date.now() - startedAt
    });
  } catch (error) {
    let message = 'failed';
    if (error instanceof Error) {
      message = error.message;
    }
    records.push({
      group: currentGroup,
      name: name,
      passed: false,
      message: message,
      durationMs: Date.now() - startedAt
    });
  }
}

export function assertTrue(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

export function assertEquals(actual: unknown, expected: unknown, message: string): void {
  if (actual !== expected) {
    throw new Error(message + ' (expected ' + String(expected) + ', received ' + String(actual) + ')');
  }
}

export function assertWithin(actual: number, low: number, high: number, message: string): void {
  if (actual < low || actual > high) {
    throw new Error(message + ' (value ' + actual + ' is outside ' + low + ' to ' + high + ')');
  }
}

/** Asserts that the body throws an EngineError carrying the given code. */
export async function assertRejectsWithCode(
  body: () => Promise<unknown>,
  expectedCode: string,
  message: string
): Promise<void> {
  let thrown: unknown = null;
  try {
    await body();
  } catch (error) {
    thrown = error;
  }
  if (thrown === null) {
    throw new Error(message + ' (nothing was thrown)');
  }
  const candidate = thrown as { code?: string };
  if (candidate.code !== expectedCode) {
    throw new Error(message + ' (expected code ' + expectedCode + ', received ' + String(candidate.code) + ')');
  }
}

export function getRecords(): CaseRecord[] {
  const out: CaseRecord[] = [];
  for (let i = 0; i < records.length; i++) {
    out.push(records[i]);
  }
  return out;
}

export interface Totals {
  passed: number;
  failed: number;
  total: number;
  passRate: number;
}

export function totals(): Totals {
  let passed = 0;
  let failed = 0;
  for (let i = 0; i < records.length; i++) {
    if (records[i].passed) {
      passed = passed + 1;
    } else {
      failed = failed + 1;
    }
  }
  let rate = 0;
  if (records.length > 0) {
    rate = Math.round((passed / records.length) * 10000) / 100;
  }
  return { passed: passed, failed: failed, total: records.length, passRate: rate };
}

/** Prints every case, then the totals. Exit code 1 when anything failed. */
export function report(title: string): Totals {
  console.log('');
  console.log(title);
  console.log(''.padEnd(title.length, '='));

  let lastGroup = '';
  for (let i = 0; i < records.length; i++) {
    const record = records[i];
    if (record.group !== lastGroup) {
      console.log('');
      console.log('  ' + record.group);
      lastGroup = record.group;
    }
    let status = 'FAIL';
    if (record.passed) {
      status = 'PASS';
    }
    let line = '    [' + status + '] ' + record.name + ' (' + record.durationMs + ' ms)';
    if (!record.passed) {
      line = line + '\n           reason: ' + record.message;
    }
    console.log(line);
  }

  const summary = totals();
  console.log('');
  console.log(
    '  ' + summary.passed + ' passed, ' + summary.failed + ' failed, ' +
    summary.total + ' total, pass rate ' + summary.passRate + ' percent'
  );
  console.log('');
  return summary;
}
