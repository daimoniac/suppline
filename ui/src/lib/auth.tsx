import { createContext, useContext, useState, useCallback, type ReactNode } from 'react';
import { APIClient } from './api';

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
  const [isAuthenticated, setIsAuthenticated] = useState(() => Boolean(localStorage.getItem(STORAGE_KEY)));

  const login = useCallback(async (key: string) => {
    apiClient.setAPIKey(key);
    try {
      await apiClient.getHealth();
      localStorage.setItem(STORAGE_KEY, key);
      setIsAuthenticated(true);
    } catch {
      apiClient.clearAPIKey();
      throw new Error('Invalid API key');
    }
  }, [apiClient]);

  const logout = useCallback(() => {
    apiClient.clearAPIKey();
    localStorage.removeItem(STORAGE_KEY);
    setIsAuthenticated(false);
  }, [apiClient]);

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
