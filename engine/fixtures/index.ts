/**
 * Fixture loader.
 *
 * This is the only file in the project that touches the file system, which
 * keeps the cryptographic modules portable: they can run unchanged in the
 * API server and in the browser.
 */

import * as fs from 'fs';
import * as path from 'path';
import { EngineError } from '../src/errors';

export interface Sha256Vector {
  name: string;
  source: string;
  inputUtf8: string;
  expectedHex: string;
}

export interface Pbkdf2Vector {
  name: string;
  source: string;
  password: string;
  saltUtf8: string;
  iterations: number;
  outputBits: number;
  expectedHex: string;
}

export interface AesGcmVector {
  name: string;
  source: string;
  keyHex: string;
  nonceHex: string;
  plaintextHex: string;
  expectedCiphertextWithTagHex: string;
}

export interface ClassicalVector {
  name: string;
  source: string;
  algorithm: 'caesar' | 'vigenere';
  inputText: string;
  shift?: number;
  keyword?: string;
  expectedText: string;
}

export interface VectorSet {
  note: string;
  sha256: Sha256Vector[];
  pbkdf2Sha256: Pbkdf2Vector[];
  aesGcm: AesGcmVector[];
  classical: ClassicalVector[];
}

export interface SafeSample {
  id: string;
  label: string;
  type: string;
  text: string;
  secondary?: string;
  shift?: number;
  iterations?: number;
  mode?: string;
  expectation: string;
}

export interface AdverseSample extends SafeSample {
  expectedIndicator: string;
}

export interface MalformedSample {
  id: string;
  label: string;
  type: string;
  text?: string;
  secondary?: string;
  shift?: number;
  iterations?: number;
  textRepeat?: { character: string; count: number };
  textWithControl?: boolean;
  expectedCode: string;
}

export interface SampleSet {
  note: string;
  safe: SafeSample[];
  adverse: AdverseSample[];
  malformed: MalformedSample[];
}

function readJsonFile(fileName: string): unknown {
  const candidates: string[] = [
    path.join(__dirname, fileName),
    path.join(__dirname, '..', '..', 'fixtures', fileName),
    path.join(process.cwd(), 'fixtures', fileName)
  ];
  for (let i = 0; i < candidates.length; i++) {
    const candidate = candidates[i];
    if (fs.existsSync(candidate)) {
      const raw = fs.readFileSync(candidate, 'utf8');
      return JSON.parse(raw);
    }
  }
  throw new EngineError('FIXTURE_UNAVAILABLE', 'The fixture file "' + fileName + '" could not be located.');
}

let cachedVectors: VectorSet | null = null;
let cachedSamples: SampleSet | null = null;

export function loadVectors(): VectorSet {
  if (cachedVectors === null) {
    cachedVectors = readJsonFile('vectors.json') as VectorSet;
  }
  return cachedVectors;
}

export function loadSamples(): SampleSet {
  if (cachedSamples === null) {
    cachedSamples = readJsonFile('samples.json') as SampleSet;
  }
  return cachedSamples;
}

/** Builds the text for a malformed sample that is described rather than stored literally. */
export function buildMalformedText(sample: MalformedSample): string {
  if (sample.textRepeat !== undefined) {
    let out = '';
    for (let i = 0; i < sample.textRepeat.count; i++) {
      out = out + sample.textRepeat.character;
    }
    return out;
  }
  if (sample.textWithControl === true) {
    return 'HELLO' + String.fromCharCode(7) + 'WORLD';
  }
  if (sample.text !== undefined) {
    return sample.text;
  }
  return '';
}
