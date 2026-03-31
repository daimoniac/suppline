import { createContext, useContext, useState, useCallback, type ReactNode } from 'react';

interface Toast {
  id: number;
  message: string;
  type: 'success' | 'error' | 'warning' | 'info';
}

interface ToastContextType {
  toasts: Toast[];
  toast: (message: string, type?: Toast['type']) => void;
  dismiss: (id: number) => void;
}

const ToastContext = createContext<ToastContextType | null>(null);
let nextId = 0;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const toast = useCallback((message: string, type: Toast['type'] = 'info') => {
    const id = nextId++;
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 4000);
  }, []);

  const dismiss = useCallback((id: number) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={{ toasts, toast, dismiss }}>
      {children}
      <div className="fixed top-4 right-4 z-50 flex flex-col gap-2 max-w-sm">
        {toasts.map(t => (
          <div
            key={t.id}
            className={`toast-enter px-4 py-3 rounded-lg border text-sm cursor-pointer shadow-lg ${
              t.type === 'success' ? 'bg-success-bg border-success/30 text-success' :
              t.type === 'error' ? 'bg-danger-bg border-danger/30 text-danger' :
              t.type === 'warning' ? 'bg-warning-bg border-warning/30 text-warning' :
              'bg-info-bg border-info/30 text-info'
            }`}
            onClick={() => dismiss(t.id)}
          >
            {t.message}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used within ToastProvider');
  return ctx;
}
