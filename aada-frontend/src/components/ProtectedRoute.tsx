import { Navigate, useLocation } from "react-router-dom";
import { useAppStore } from "@/store/appStore";

/** Gate: redirect to /login when there is no token, preserving the intended path. */
export function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const token = useAppStore((s) => s.token);
  const location = useLocation();
  if (!token) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  return <>{children}</>;
}
