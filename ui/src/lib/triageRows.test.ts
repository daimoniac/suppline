import { describe, expect, it } from 'vitest';
import { runSummary } from './triageRows';

describe('runSummary', () => {
  it('names the written state', () => {
    expect(runSummary({ Status: 'committed', Verdict: 'not_affected', WrittenState: 'not_affected', Confidence: 0.92 }))
      .toBe('Committed · wrote Not affected · model confidence 0.92');
  });

  it('says when the guard wrote something other than the model verdict', () => {
    expect(runSummary({ Status: 'committed', Verdict: 'not_affected', WrittenState: 'affected', Confidence: 0.9 }))
      .toBe('Committed · wrote Affected, model said Not affected · model confidence 0.90');
  });

  it('keeps the model verdict apart from the status of a run that wrote nothing', () => {
    expect(runSummary({ Status: 'rejected_by_guardrail', Verdict: 'uncertain', Confidence: 0.5 }))
      .toBe('Rejected · model said Uncertain · model confidence 0.50');
  });

  it('describes a dry run as what it would write', () => {
    expect(runSummary({ Status: 'dry_run', Verdict: 'not_affected', WrittenState: 'not_affected', Confidence: 0 }))
      .toBe('Dry run · would write Not affected');
  });

  it('shows an older committed run without a written state by its model verdict', () => {
    expect(runSummary({ Status: 'committed', Verdict: 'uncertain', Confidence: 0.5 }))
      .toBe('Committed · model said Uncertain · model confidence 0.50');
  });
});
