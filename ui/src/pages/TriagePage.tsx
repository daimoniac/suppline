import { useSearchParams } from 'react-router';
import { PageHeader } from '../components/ui';
import { TriageBoard } from '../components/TriageBoard';
import { TriageRepositories } from '../components/TriageRepositories';

const STATEMENT_PARAMS = ['cve_id', 'repository', 'state', 'expiration_status'];

export default function TriagePage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const requested = searchParams.get('view');
  const deepLinked = STATEMENT_PARAMS.some(name => searchParams.has(name));
  const view = requested === 'statements' || (requested !== 'repositories' && deepLinked) ? 'statements' : 'repositories';

  const choose = (next: 'repositories' | 'statements') => {
    const params = new URLSearchParams(searchParams);
    params.set('view', next);
    setSearchParams(params, { replace: true });
  };

  return (
    <div>
      <PageHeader title="Triage" subtitle="Which CVEs block running images, what triage decided, and why it left some alone" />
      <div className="inline-flex mb-4 p-0.5 rounded-lg border border-border bg-bg-secondary text-sm" role="group" aria-label="Triage view">
        {([['repositories', 'Repositories'], ['statements', 'Statements']] as const).map(([value, label]) => (
          <button key={value} type="button" onClick={() => choose(value)} aria-pressed={view === value}
            className={`px-3 py-1.5 rounded-md transition-colors ${view === value ? 'bg-bg-tertiary text-text-primary font-medium' : 'text-text-secondary hover:text-text-primary'}`}>
            {label}
          </button>
        ))}
      </div>
      {view === 'repositories' ? <TriageRepositories /> : <TriageBoard />}
    </div>
  );
}
