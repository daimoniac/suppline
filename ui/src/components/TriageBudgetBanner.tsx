export interface TriageBudgetState {
  used: number;
  limit: number;
  exhausted: boolean;
}

export function TriageBudgetBanner({
  budget,
  resetting,
  onReset,
}: {
  budget: TriageBudgetState;
  resetting: boolean;
  onReset: () => void;
}) {
  if (budget.limit <= 0) return null;
  return (
    <div className={`mb-4 flex flex-wrap items-center justify-between gap-3 px-4 py-3 rounded-xl border text-sm ${budget.exhausted ? 'bg-warning-bg border-warning/30 text-warning' : 'bg-bg-primary border-border text-text-secondary'}`}>
      <div>
        <span className="font-medium text-text-primary">{budget.used.toLocaleString()} / {budget.limit.toLocaleString()}</span>
        <span> tokens today</span>
        {budget.exhausted && <span> · triage is waiting until the limit resets</span>}
      </div>
      <button
        type="button"
        onClick={onReset}
        disabled={resetting || budget.used === 0}
        className="px-3 py-1.5 text-xs rounded-lg border border-border bg-bg-secondary text-text-primary hover:bg-bg-tertiary transition-colors disabled:opacity-50"
      >
        {resetting ? 'Resetting…' : 'Reset daily limit'}
      </button>
    </div>
  );
}
