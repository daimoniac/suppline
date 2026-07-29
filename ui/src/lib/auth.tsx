import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from 'react';
import { APIClient, APIError } from './api';

interface AuthContextType {
  isAuthenticated: boolean;
  apiClient: APIClient;
  login: (key: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | null>(null);

const STORAGE_KEY = 'stk_api_key';

export function AuthProvider({ children }: { children: ReactNode }) {
  const [apiClient] = useState(() => {
    const client = new APIClient();
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      client.setAPIKey(stored);
    }
    return client;
  });
  // null = still validating a stored key; avoid flashing the shell with a bad key
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(() =>
    localStorage.getItem(STORAGE_KEY) ? null : false,
  );

  const logout = useCallback(() => {
    apiClient.clearAPIKey();
    localStorage.removeItem(STORAGE_KEY);
    setIsAuthenticated(false);
  }, [apiClient]);

  const login = useCallback(async (key: string) => {
    apiClient.setAPIKey(key);
    try {
      // /health is unauthenticated — probe a protected route instead
      await apiClient.getScans({ limit: 1 });
      localStorage.setItem(STORAGE_KEY, key);
      setIsAuthenticated(true);
    } catch {
      apiClient.clearAPIKey();
      throw new Error('Invalid API key');
    }
  }, [apiClient]);

  // Validate stored key on mount; clear it if the backend rejects it (e.g. switched to eval "demo")
  useEffect(() => {
    if (isAuthenticated !== null) return;
    let cancelled = false;
    (async () => {
      try {
        await apiClient.getScans({ limit: 1 });
        if (!cancelled) setIsAuthenticated(true);
      } catch (e: unknown) {
        if (!cancelled) {
          if (e instanceof APIError && e.status === 401) {
            logout();
          } else {
            // Network blip: keep the key but treat as logged in so Retry can work
            setIsAuthenticated(true);
          }
        }
      }
    })();
    return () => { cancelled = true; };
  }, [apiClient, isAuthenticated, logout]);

  // Any 401 from the client should bounce back to the login screen
  useEffect(() => {
    return apiClient.onUnauthorized(() => {
      logout();
    });
  }, [apiClient, logout]);

  if (isAuthenticated === null) {
    return (
      <div className="min-h-screen bg-surface flex items-center justify-center text-text-secondary text-sm">
        Checking authentication…
      </div>
    );
  }

  return (
    <AuthContext.Provider value={{ isAuthenticated, apiClient, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
