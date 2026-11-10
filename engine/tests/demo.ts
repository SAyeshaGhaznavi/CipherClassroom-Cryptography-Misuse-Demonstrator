/**
 * Walks the guided sequence from FR-1 and prints each stage.
 *
 * This is the script to run during the recorded demonstration: it shows the
 * full input to result workflow in the order the specification sets out.
 *
 * Run with: npm run demo
 */

import { runGuidedSequence, summariseSequence } from '../src/engine';
import { getPolicy, resetPolicy } from '../src/policy';
import type { AuditEventDraft } from '../src/types';

async function main(): Promise<void> {
  resetPolicy();
  const auditLog: AuditEventDraft[] = [];

  console.log('');
  console.log('CipherClassroom guided experiment sequence');
  console.log('=========================================');
  console.log('Policy version: ' + getPolicy().policyVersion);
  console.log('');

  const steps = await runGuidedSequence('Meet at the library at noon to collect the lab report.', {
    actor: 'operator-demo',
    onAuditEvent: (event) => {
      auditLog.push(event);
    }
  });

  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const result = step.result;
    console.log('Step ' + step.step + ': ' + result.title);
    console.log('  severity : ' + result.severity);
    console.log('  rule     : ' + result.engine.ruleName);
    console.log('  summary  : ' + result.summary);
    for (let j = 0; j < result.details.length; j++) {
      const detail = result.details[j];
      let value = detail.value;
      if (value.length > 90) {
        value = value.substring(0, 87) + '...';
      }
      console.log('    - ' + detail.label + ': ' + value);
    }
    if (result.warnings.length > 0) {
      for (let j = 0; j < result.warnings.length; j++) {
        console.log('    ! ' + result.warnings[j]);
      }
    }
    console.log('  duration : ' + result.durationMs + ' ms');
    console.log('');
  }

  const summary = summariseSequence(steps);
  console.log('Sequence summary');
  console.log('  steps          : ' + summary.totalSteps);
  console.log('  critical       : ' + summary.criticalFindings);
  console.log('  warning        : ' + summary.warningFindings);
  console.log('  informational  : ' + summary.informationalFindings);
  console.log('  total duration : ' + summary.totalDurationMs + ' ms');
  console.log('  rules applied  : ' + summary.ruleNames.join(', '));
  console.log('');
  console.log('Audit events offered to the repository layer: ' + auditLog.length);
  for (let i = 0; i < auditLog.length; i++) {
    const event = auditLog[i];
    console.log('  ' + event.timestamp + '  ' + event.action + '  ' + event.outcome + '  ' + event.detail);
  }
  console.log('');
}

main().catch((error) => {
  console.error('The demonstration could not complete:', error);
  process.exitCode = 1;
});
