/**
 * Public surface of the CipherClassroom security engine (Member B).
 *
 * The API layer should import from this file only. Everything exported here
 * is an independently testable function with no storage, no network access
 * and no dependency on any web framework.
 */

export { runExperiment, runGuidedSequence, summariseSequence, ENGINE_VERSION } from './engine';
export type { GuidedStep, SequenceSummary } from './engine';

export { EngineError, toSafeError } from './errors';
export type { EngineErrorCode, SafeErrorResponse } from './errors';

export { getPolicy, getDefaultPolicy, updatePolicy, resetPolicy } from './policy';
export type { LabPolicy, PolicyChange, PolicyUpdateResult } from './policy';

export { listSupportedTypes, normalizeText } from './util/validate';

export { loadVectors, loadSamples } from '../fixtures';
export { runTestVectors } from './modules/testVectors';

export * from './types';
