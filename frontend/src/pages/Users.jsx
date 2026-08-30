import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getUsers, updateUserRole, updateUserStatus } from "../api/client";
import { useAuth } from "../context/AuthContext.jsx";

const ROLES = ["admin", "analyst", "viewer"];

export default function Users() {
  const { user: me } = useAuth();
  const queryClient = useQueryClient();

  const { data: users, isLoading } = useQuery({ queryKey: ["users"], queryFn: getUsers });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["users"] });

  const roleMutation = useMutation({
    mutationFn: ({ id, role }) => updateUserRole(id, role),
    onSuccess: invalidate,
  });
  const statusMutation = useMutation({
    mutationFn: ({ id, is_active }) => updateUserStatus(id, is_active),
    onSuccess: invalidate,
  });

  return (
    <div>
      <h2>Users</h2>

      {isLoading ? (
        <p>Loading…</p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>Email</th><th>Role</th><th>Status</th><th>Created</th><th></th>
            </tr>
          </thead>
          <tbody>
            {(users ?? []).map((u) => {
              const isSelf = u.id === me.id;
              return (
                <tr key={u.id}>
                  <td>{u.email}{isSelf && <span className="self-badge"> (you)</span>}</td>
                  <td>
                    <select
                      value={u.role}
                      disabled={isSelf || roleMutation.isPending}
                      onChange={(e) => roleMutation.mutate({ id: u.id, role: e.target.value })}
                    >
                      {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                    </select>
                  </td>
                  <td>
                    <span className={`pill ${u.is_active ? "pill-active" : "pill-inactive"}`}>
                      {u.is_active ? "active" : "disabled"}
                    </span>
                  </td>
                  <td>{u.created_at ? new Date(u.created_at).toLocaleString() : "—"}</td>
                  <td>
                    <button
                      disabled={isSelf && u.is_active || statusMutation.isPending}
                      onClick={() => statusMutation.mutate({ id: u.id, is_active: !u.is_active })}
                    >
                      {u.is_active ? "Disable" : "Enable"}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      {(roleMutation.isError || statusMutation.isError) && (
        <p className="auth-error">
          {roleMutation.error?.response?.data?.error || statusMutation.error?.response?.data?.error}
        </p>
      )}
    </div>
  );
}
