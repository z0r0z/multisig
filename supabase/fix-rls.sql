-- Drop old restrictive policies and replace with permissive ones.
-- Run this if you already applied the original schema.sql.

do $$ begin
  -- wallets
  drop policy if exists wallets_read on wallets;
  drop policy if exists wallets_insert on wallets;
  drop policy if exists wallets_update on wallets;
  create policy wallets_all on wallets for all using (true) with check (true);

  -- owners
  drop policy if exists owners_read on owners;
  drop policy if exists owners_insert on owners;
  drop policy if exists owners_update on owners;
  create policy owners_all on owners for all using (true) with check (true);

  -- transactions
  drop policy if exists tx_read on transactions;
  drop policy if exists tx_insert on transactions;
  drop policy if exists tx_update on transactions;
  create policy tx_all on transactions for all using (true) with check (true);

  -- signatures
  drop policy if exists sigs_read on signatures;
  drop policy if exists sigs_insert on signatures;
  create policy sigs_all on signatures for all using (true) with check (true);

  -- approvals
  drop policy if exists approvals_read on approvals;
  drop policy if exists approvals_insert on approvals;
  drop policy if exists approvals_update on approvals;
  create policy approvals_all on approvals for all using (true) with check (true);

  -- config_log
  drop policy if exists config_read on config_log;
  drop policy if exists config_insert on config_log;
  create policy config_all on config_log for all using (true) with check (true);
end $$;
