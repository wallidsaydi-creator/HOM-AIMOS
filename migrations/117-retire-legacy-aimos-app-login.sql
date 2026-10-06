-- The historical aimos_app role was created with a fixed password in
-- migration 002. No serving or maintenance code connects as this role.
-- Retain the role and its historical grants for audit continuity, but remove
-- its ability to authenticate. Migration 002 remains immutable.

ALTER ROLE aimos_app NOLOGIN PASSWORD NULL;
