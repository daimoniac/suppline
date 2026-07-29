/**
 * Defer effect-driven loads so setState does not run synchronously inside
 * useEffect (react-hooks/set-state-in-effect).
 */
export function scheduleEffectLoad(load: () => void | Promise<void>): void {
  queueMicrotask(() => {
    void load();
  });
}
