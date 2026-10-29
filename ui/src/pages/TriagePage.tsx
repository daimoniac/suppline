import { PageHeader } from '../components/ui';
import { TriageBoard } from '../components/TriageBoard';

export default function TriagePage() {
  return (
    <div>
      <PageHeader title="Triage" subtitle="Automated and hand-written decisions on whether a finding affects this environment" />
      <TriageBoard mode="full" />
    </div>
  );
}
