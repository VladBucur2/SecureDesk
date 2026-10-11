-- Least-privilege grants for the application account (SC-06), MySQL only.
--
-- Re-applied by Flyway whenever this file changes, so a table added in a later migration gets
-- its grant here. The application account has no DDL rights and no database-wide grants: every
-- table is listed with exactly the statements the API needs.

-- Accounts are disabled or erased, never deleted, so there is no DELETE.
GRANT SELECT, INSERT, UPDATE ON app_user TO '${app_user}'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON recovery_code TO '${app_user}'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON login_throttle TO '${app_user}'@'%';

-- Categories are deactivated, never deleted.
GRANT SELECT, INSERT, UPDATE ON category TO '${app_user}'@'%';

-- DELETE is needed by the retention job and by erasure of a user's data (SR-10).
GRANT SELECT, INSERT, UPDATE, DELETE ON ticket TO '${app_user}'@'%';
GRANT SELECT, INSERT, DELETE ON ticket_comment TO '${app_user}'@'%';
GRANT SELECT, INSERT, DELETE ON attachment TO '${app_user}'@'%';
GRANT SELECT, INSERT, DELETE ON attachment_content TO '${app_user}'@'%';

GRANT SELECT, INSERT, UPDATE ON app_setting TO '${app_user}'@'%';

-- Append-only below the application: no UPDATE, no DELETE (UC-07, SC-09).
GRANT SELECT, INSERT ON audit_event TO '${app_user}'@'%';
