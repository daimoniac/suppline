import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './lib/auth';
import { ToastProvider } from './lib/toast';
import Layout from './components/Layout';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import RepositoriesPage from './pages/RepositoriesPage';
import RepositoryDetailPage from './pages/RepositoryDetailPage';
import ScansPage from './pages/ScansPage';
import ScanDetailPage from './pages/ScanDetailPage';
import FailedImagesPage from './pages/FailedImagesPage';
import VulnerabilitiesPage from './pages/VulnerabilitiesPage';
import VEXPage from './pages/VEXPage';
import IntegrationsPage from './pages/IntegrationsPage';

function AppRoutes() {
  const { isAuthenticated } = useAuth();

  if (!isAuthenticated) return <LoginPage />;

  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<DashboardPage />} />
        <Route path="repositories" element={<RepositoriesPage />} />
        <Route path="repositories/:name" element={<RepositoryDetailPage />} />
        <Route path="repositories/:name/tags/:digest" element={<ScanDetailPage />} />
        <Route path="scans" element={<ScansPage />} />
        <Route path="scans/:digest" element={<ScanDetailPage />} />
        <Route path="failed" element={<FailedImagesPage />} />
        <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
        <Route path="vex" element={<VEXPage />} />
        <Route path="tolerations" element={<Navigate to="/vex" replace />} />
        <Route path="integrations" element={<IntegrationsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <ToastProvider>
          <AppRoutes />
        </ToastProvider>
      </AuthProvider>
    </BrowserRouter>
  );
}
