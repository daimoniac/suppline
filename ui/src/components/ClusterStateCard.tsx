import { Crown, Network } from 'lucide-react';
import type { ClusterInstance } from '../lib/api';
import { cn } from '../lib/utils';

/** Dashboard card: the running suppline instances, the leader highlighted. */
export function ClusterStateCard({ instances }: { instances: ClusterInstance[] }) {
  return (
    <div className="bg-bg-primary border border-success/20 rounded-xl p-4 min-w-0">
      <div className="text-success mb-3"><Network className="w-5 h-5" /></div>
      <div className="text-xs text-text-secondary mb-2">Cluster state</div>
      {instances.length === 0 ? (
        <div className="text-xs text-text-muted">No instance reported</div>
      ) : (
        <ul className="space-y-1">
          {instances.map(instance => (
            <li
              key={instance.Hostname}
              data-leader={instance.Leader ? 'true' : 'false'}
              title={`${instance.Hostname} · ${instance.Leader ? 'leader' : 'standby'} · ${healthLabel(instance)} · ${instance.Version}`}
              className={cn(
                'flex items-center gap-1.5 text-xs font-mono rounded px-1.5 py-0.5 min-w-0',
                instance.Leader ? 'bg-success/10 text-success font-semibold' : 'text-text-secondary',
              )}
            >
              <span
                data-health={instance.Healthy ? 'healthy' : 'unhealthy'}
                aria-label={healthLabel(instance)}
                className={cn('w-2 h-2 rounded-full flex-shrink-0', instance.Healthy ? 'bg-success' : 'bg-danger')}
              />
              {instance.Leader ? <Crown className="w-3 h-3 flex-shrink-0" /> : <span className="w-3 h-3 flex-shrink-0" />}
              {/* rtl puts the ellipsis on the left; the LRMs keep the name itself left-to-right. */}
              <span className="truncate min-w-0" style={{ direction: 'rtl', textAlign: 'left' }}>{'‎'}{instance.Hostname}{'‎'}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Why a pod is green or red, for the tooltip. */
function healthLabel(instance: ClusterInstance): string {
  if (instance.Healthy) return 'healthy';
  if (instance.Status === 'healthy') return `unhealthy (no heartbeat since ${new Date(instance.SeenAt * 1000).toLocaleTimeString()})`;
  return 'unhealthy';
}
