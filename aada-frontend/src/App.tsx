import { Routes, Route } from "react-router-dom";
import { AppLayout } from "@/components/layout/AppLayout";
import { ProtectedRoute } from "@/components/ProtectedRoute";
import Login from "@/pages/Login";
import Triage from "@/pages/Triage";
import Simulator from "@/pages/Simulator";
import Alerts from "@/pages/Alerts";
import Investigations from "@/pages/Investigations";
import Reports from "@/pages/Reports";
import Settings from "@/pages/Settings";

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        element={
          <ProtectedRoute>
            <AppLayout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Triage />} />
        <Route path="simulator" element={<Simulator />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="investigations" element={<Investigations />} />
        <Route path="reports" element={<Reports />} />
        <Route path="settings" element={<Settings />} />
      </Route>
    </Routes>
  );
}
