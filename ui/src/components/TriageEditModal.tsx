import { useEffect, useState } from 'react';
import { useAuth } from '../lib/auth';
import { formatDate } from '../lib/utils';
import { SeverityBadge } from './ui';
import { scheduleEffectLoad } from '../lib/scheduleEffectLoad';
import { STATUS_LABELS, VEX_JUSTIFICATIONS, VEX_STATES, fromLocalInput, toLocalInput, type StatementRow } from '../lib/triageRows';
import type { TriageAccept, VulnerabilityGroup } from '../lib/api';

export function EditModal({
  row,
  withCVEs,
  onClose,
  onSave,
}: {
  row: StatementRow;
  withCVEs: string[];
  onClose: () => void;
  onSave: (body: TriageAccept) => Promise<void>;
}) {
  const { apiClient } = useAuth();
  const knownState = VEX_STATES.some(([value]) => value === row.state);
  const [state, setState] = useState(knownState ? row.state : 'not_affected');
  const [justification, setJustification] = useState(row.justification || 'code_not_reachable');
  const [detail, setDetail] = useState(row.detail);
  const [expires, setExpires] = useState(toLocalInput(row.expiresAt));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [vuln, setVuln] = useState<VulnerabilityGroup | null>(null);
  const [vulnState, setVulnState] = useState<'loading' | 'ready' | 'missing'>('loading');

  useEffect(() => {
    let cancelled = false;
    scheduleEffectLoad(async () => {
      try {
        const details = await apiClient.getVulnerabilityDetails(row.cve, { max_digests: 20 });
        if (cancelled) return;
        setVuln(details);
        setVulnState(details?.CVEID ? 'ready' : 'missing');
      } catch {
        if (!cancelled) setVulnState('missing');
      }
    });
    return () => { cancelled = true; };
  }, [apiClient, row.cve]);

  const packages = [...new Set(
    (vuln?.affected || []).flatMap(image => (image.digests || []).map(digest => digest.packageName).filter(Boolean)),
  )];

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      await onSave({
        Repository: row.repository,
        CVEID: row.cve,
        State: state,
        Justification: state === 'not_affected' ? justification : undefined,
        Detail: detail.trim() || undefined,
        ExpiresAt: fromLocalInput(expires),
      });
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to save');
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div className="bg-bg-secondary border border-border rounded-xl shadow-2xl w-full max-w-5xl max-h-[90vh] flex flex-col" onClick={e => e.stopPropagation()}>
        <div className="flex items-center gap-3 px-6 pt-5 pb-4 border-b border-border shrink-0">
          <h3 className="text-lg font-semibold font-mono">{row.cve}</h3>
          {vuln?.Severity && <SeverityBadge severity={vuln.Severity} />}
          <p className="text-xs text-text-muted truncate ml-auto">{row.repository}</p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 min-h-0 overflow-y-auto md:overflow-hidden md:flex-1">
          <div className="px-6 py-5 space-y-4 border-b md:border-b-0 md:border-r border-border md:overflow-y-auto">
            {vulnState === 'loading' && <p className="text-sm text-text-muted">Loading vulnerability…</p>}
            {vulnState === 'missing' && (
              <p className="text-sm text-text-secondary">This CVE has no vulnerability record in the current scans.</p>
            )}
            {vuln && (
              <div className="space-y-2 text-sm">
                {vuln.Title && <p className="font-medium text-text-primary">{vuln.Title}</p>}
                {vuln.Description && <p className="text-text-secondary whitespace-pre-wrap">{vuln.Description}</p>}
                <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-text-muted">
                  <span>{vuln.affectedImageCount || row.affectedImages} affected image{(vuln.affectedImageCount || row.affectedImages) === 1 ? '' : 's'}</span>
                  {packages.length > 0 && <span>Package: {packages.slice(0, 3).join(', ')}{packages.length > 3 ? ` +${packages.length - 3}` : ''}</span>}
                </div>
                {vuln.PrimaryURL && (
                  <a href={vuln.PrimaryURL} target="_blank" rel="noreferrer" className="text-xs text-accent hover:text-accent-hover break-all">
                    {vuln.PrimaryURL}
                  </a>
                )}
              </div>
            )}
            <div className="text-sm border-t border-border pt-4">
              <p className="text-xs text-text-muted mb-2">
                Automated triage
                {row.run ? ` · ${STATUS_LABELS[row.run.Status] || row.run.Status} · ${row.run.Confidence.toFixed(2)} confidence` : ''}
              </p>
              {withCVEs.length > 0 && (
                <p className="text-xs text-text-muted mb-2">Triaged with {withCVEs.join(', ')}</p>
              )}
              {row.run?.Reasoning ? (
                <p className="text-text-secondary whitespace-pre-wrap">{row.run.Reasoning}</p>
              ) : (
                <p className="text-text-muted">No automated triage notes for this statement.</p>
              )}
            </div>
          </div>
          <div className="px-6 py-5 md:overflow-y-auto">
            <div className="space-y-3">
              <label className="block text-xs text-text-secondary">
                Outcome
                <select value={state} onChange={e => setState(e.target.value)}
                  className="mt-1 w-full px-3 py-2 bg-bg-primary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50">
                  {VEX_STATES.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                </select>
              </label>
              {state === 'not_affected' && (
                <label className="block text-xs text-text-secondary">
                  Justification
                  <select value={justification} onChange={e => setJustification(e.target.value)}
                    className="mt-1 w-full px-3 py-2 bg-bg-primary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50">
                    {VEX_JUSTIFICATIONS.map(value => <option key={value} value={value}>{value}</option>)}
                  </select>
                </label>
              )}
              <label className="block text-xs text-text-secondary">
                Detail
                <textarea value={detail} onChange={e => setDetail(e.target.value)} rows={8}
                  className="mt-1 w-full px-3 py-2 bg-bg-primary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50" />
              </label>
              <label className="block text-xs text-text-secondary">
                Expires
                <input type="datetime-local" value={expires} onChange={e => setExpires(e.target.value)}
                  className="mt-1 w-full px-3 py-2 bg-bg-primary border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent/50" />
              </label>
              {expires && <p className="text-xs text-text-muted">Expires {formatDate(fromLocalInput(expires) || 0)}</p>}
              {error && <p className="text-sm text-danger">{error}</p>}
            </div>
            <div className="flex justify-end gap-3 mt-6">
              <button type="button" onClick={onClose} className="px-4 py-2 text-sm rounded-lg border border-border text-text-secondary hover:bg-bg-tertiary transition-colors">Cancel</button>
              <button type="button" onClick={save} disabled={saving} className="px-4 py-2 text-sm rounded-lg bg-accent text-bg-primary font-medium hover:bg-accent-hover transition-colors disabled:opacity-50">
                {saving ? 'Saving…' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
