import { BrowserRouter, Navigate, Route, Routes } from "react-router";
import { AuthProvider } from "./auth";
import { Home, Layout, RequireRole } from "./components/Layout";
import { StepUpProvider } from "./components/StepUp";
import { AccountPage } from "./pages/Account";
import { AuditPage } from "./pages/admin/Audit";
import { CategoriesPage, RetentionPage } from "./pages/admin/Settings";
import { UsersPage } from "./pages/admin/Users";
import { QueuePage } from "./pages/agent/Queue";
import { QueueTicketPage } from "./pages/agent/QueueTicket";
import { MyTicketsPage } from "./pages/requester/MyTickets";
import { NewTicketPage } from "./pages/requester/NewTicket";
import { RequesterTicketPage } from "./pages/requester/TicketView";
import { CodePage, EnrolPage, LoginPage, NewPasswordPage } from "./pages/SignIn";

export function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <StepUpProvider>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/login/code" element={<CodePage />} />
            <Route path="/login/enrol" element={<EnrolPage />} />
            <Route path="/login/new-password" element={<NewPasswordPage />} />
            <Route element={<Layout />}>
              <Route index element={<Home />} />
              <Route path="/account" element={<AccountPage />} />
              <Route path="/tickets" element={<RequireRole role="REQUESTER"><MyTicketsPage /></RequireRole>} />
              <Route path="/tickets/new" element={<RequireRole role="REQUESTER"><NewTicketPage /></RequireRole>} />
              <Route path="/tickets/:id" element={<RequireRole role="REQUESTER"><RequesterTicketPage /></RequireRole>} />
              <Route path="/queue" element={<RequireRole role="AGENT"><QueuePage /></RequireRole>} />
              <Route path="/queue/:id" element={<RequireRole role="AGENT"><QueueTicketPage /></RequireRole>} />
              <Route path="/admin/users" element={<RequireRole role="ADMIN"><UsersPage /></RequireRole>} />
              <Route path="/admin/categories" element={<RequireRole role="ADMIN"><CategoriesPage /></RequireRole>} />
              <Route path="/admin/retention" element={<RequireRole role="ADMIN"><RetentionPage /></RequireRole>} />
              <Route path="/admin/audit" element={<RequireRole role="ADMIN"><AuditPage /></RequireRole>} />
            </Route>
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </StepUpProvider>
      </AuthProvider>
    </BrowserRouter>
  );
}
