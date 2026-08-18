import { createAccessControl } from 'better-auth/plugins';
import { adminAc, defaultStatements } from 'better-auth/plugins/admin/access';

export const appAc = createAccessControl({
  // better-auth admin plugin resources (user, session) — required so its
  // endpoints (list/ban/impersonate) can authorize against our custom roles.
  ...defaultStatements,
  // bit's own resource: ingesting vuln-knowledge records vs. reading them.
  record: ['ingest', 'read'],
  // Gate for the HTTP admin doorway. Granted to `admin` only; the doorway can
  // `requirePermissions({ management: ['access'] })` to lock itself down.
  management: ['access']
});

// Admin can trigger ingestion and everything else (plus the admin plugin's own
// user/session management permissions), including the HTTP admin doorway gate.
export const adminRole = appAc.newRole({
  ...adminAc.statements,
  record: ['ingest', 'read'],
  management: ['access']
});

// User can do everything except ingestion: retrieval + managing their own keys.
export const userRole = appAc.newRole({
  record: ['read']
});

export const roles = {
  admin: adminRole,
  user: userRole
};

export type Role = keyof typeof roles;

export const isSupportedRole = (input: string): input is Role =>
  Object.prototype.hasOwnProperty.call(roles, input);
