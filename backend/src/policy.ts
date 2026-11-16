/**
 * Keeps the engine's lab policy across server restarts.
 *
 * ENGINE_CONTRACT.md: "the policy lives in memory in this version, so it
 * resets when the server restarts. If you want it to survive a restart,
 * persist it in your repository layer and call updatePolicy with the stored
 * values at startup."
 */
import { getPolicy, resetPolicy, updatePolicy } from 'cipherclassroom-engine';
import type { Repositories } from './repositories';

/** The fields an administrator may change (listed in ENGINE_CONTRACT.md). */
export const EDITABLE_POLICY_FIELDS = [
  'maxInputLength',
  'criticalKdfIterations',
  'minSafeKdfIterations',
  'maxKdfIterations',
  'minAvalancheBits',
  'maxAvalancheBits',
  'minVigenereKeywordLength'
];

/** Saves the current editable policy values to the database. */
export function saveCurrentPolicy(repos: Repositories): void {
  const policy = getPolicy() as unknown as Record<string, number>;
  const values: Record<string, number> = {};
  for (const field of EDITABLE_POLICY_FIELDS) {
    values[field] = policy[field];
  }
  repos.settings.savePolicy(values);
}

/** Called once at startup: starts from the defaults, then applies the saved values. */
export function restoreSavedPolicy(repos: Repositories): void {
  resetPolicy();
  const saved = repos.settings.loadPolicy();
  if (saved === null) {
    return;
  }
  try {
    updatePolicy(saved);
  } catch (error) {
    console.warn('Saved lab policy could not be applied, using the defaults instead.', error);
    resetPolicy();
  }
}
