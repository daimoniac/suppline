import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from 'react';
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
  const [apiClient] = useState(() => new APIClient());
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  useEffect(() => {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      apiClient.setAPIKey(stored);
      setIsAuthenticated(true);
    }
  }, [apiClient]);

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
