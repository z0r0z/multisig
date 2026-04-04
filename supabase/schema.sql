-- Multisig Supabase Schema
-- Supports: Ethereum (1), Base (8453), Sepolia (11155111), Base Sepolia (84532)

-- ============================================================
-- Wallets
-- ============================================================

create table wallets (
  id          uuid primary key default gen_random_uuid(),
  chain_id    int not null,
  address     text not null,
  deployer    text not null,
  salt        numeric not null,
  threshold   smallint not null,
  owner_count smallint not null,
  delay       int not null default 0,
  executor    text not null default '0x0000000000000000000000000000000000000000',
  nonce       int not null default 0,
  created_at  timestamptz not null default now(),
  created_block bigint,
  created_tx  text,

  unique (chain_id, address)
);

create index idx_wallets_chain on wallets (chain_id);

-- ============================================================
-- Owners
-- ============================================================
-- Current and historical owners. is_current = false after removal.
-- Position tracks linked-list order (0-indexed) for removeOwner prev lookup.

create table owners (
  id            uuid primary key default gen_random_uuid(),
  wallet_id     uuid not null references wallets on delete cascade,
  address       text not null,
  position      smallint not null default 0,
  is_current    boolean not null default true,
  added_at      timestamptz not null default now(),
  added_block   bigint,
  removed_at    timestamptz,
  removed_block bigint
);

create index idx_owners_wallet on owners (wallet_id) where is_current = true;
create index idx_owners_address on owners (address, is_current) where is_current = true;
create unique index idx_owners_unique on owners (wallet_id, address) where is_current = true;

-- ============================================================
-- Transactions (proposals)
-- ============================================================
-- A proposed multisig tx. Status tracks lifecycle:
--   proposed → signed → executing → queued → executed
--                                 → cancelled
--                     → executed  (no delay)

create type tx_status as enum ('proposed', 'executing', 'queued', 'executed', 'cancelled', 'failed');

create table transactions (
  id            uuid primary key default gen_random_uuid(),
  wallet_id     uuid not null references wallets on delete cascade,
  chain_id      int not null,
  nonce         int not null,
  target        text not null,
  value         numeric not null default 0,
  call_data     text not null default '0x',
  tx_hash       text not null,              -- EIP-712 hash
  status        tx_status not null default 'proposed',
  threshold     smallint not null,          -- snapshot at proposal time
  description   text,                       -- human-readable label
  proposed_by   text,                       -- address of proposer
  proposed_at   timestamptz not null default now(),

  -- queue / timelock
  eta           bigint,                     -- unix timestamp when executable
  queued_at     timestamptz,
  queued_block  bigint,

  -- execution
  executed_at   timestamptz,
  executed_block bigint,
  execution_tx  text,                       -- on-chain tx hash of execute call

  -- cancellation
  cancelled_at  timestamptz,
  cancelled_by  text,

  unique (wallet_id, nonce),
  unique (chain_id, tx_hash)
);

create index idx_tx_wallet_status on transactions (wallet_id, status);
create index idx_tx_chain on transactions (chain_id);
create index idx_tx_proposed_by on transactions (proposed_by);

-- ============================================================
-- Signatures
-- ============================================================
-- Collected off-chain ECDSA signatures for a transaction.
-- Ordered by signer address ascending (contract requirement).

create type sig_type as enum ('ecdsa', 'approval', 'sender');

create table signatures (
  id            uuid primary key default gen_random_uuid(),
  tx_id         uuid not null references transactions on delete cascade,
  signer        text not null,
  sig_type      sig_type not null default 'ecdsa',
  signature     text not null,              -- full 0x-prefixed 65-byte hex
  signed_at     timestamptz not null default now(),

  unique (tx_id, signer)
);

create index idx_sigs_tx on signatures (tx_id);

-- ============================================================
-- Approvals (on-chain)
-- ============================================================
-- Tracks approve(hash, bool) calls. Separate from off-chain sigs
-- because these are on-chain state that can be revoked.

create table approvals (
  id            uuid primary key default gen_random_uuid(),
  wallet_id     uuid not null references wallets on delete cascade,
  chain_id      int not null,
  owner         text not null,
  tx_hash       text not null,              -- the hash being approved
  approved      boolean not null default true,
  block_number  bigint,
  approval_tx   text,                       -- on-chain tx hash
  updated_at    timestamptz not null default now(),

  unique (wallet_id, owner, tx_hash)
);

create index idx_approvals_hash on approvals (tx_hash) where approved = true;

-- ============================================================
-- Configuration history
-- ============================================================
-- Append-only log of wallet config changes for audit / validation.

create type config_event as enum (
  'init', 'threshold_changed', 'delay_changed',
  'executor_changed', 'owner_added', 'owner_removed'
);

create table config_log (
  id            uuid primary key default gen_random_uuid(),
  wallet_id     uuid not null references wallets on delete cascade,
  event         config_event not null,
  block_number  bigint,
  tx_hash       text,
  threshold     smallint,
  delay         int,
  executor      text,
  owner_count   smallint,
  subject       text,                       -- address of added/removed owner
  created_at    timestamptz not null default now()
);

create index idx_config_wallet on config_log (wallet_id, created_at);

-- ============================================================
-- Views
-- ============================================================

-- My multisigs: find all wallets where a given address is a current owner.
-- Query: select * from my_wallets where owner = '0x...'
create view my_wallets as
  select
    w.*,
    o.address as owner
  from wallets w
  join owners o on o.wallet_id = w.id and o.is_current = true;

-- Transaction summary with signature progress.
create view tx_summary as
  select
    t.*,
    count(s.id) as sig_count,
    t.threshold as sigs_needed,
    count(s.id) >= t.threshold as ready,
    case
      when t.status = 'queued' and t.eta is not null
        then t.eta <= extract(epoch from now())
      else false
    end as queue_ready
  from transactions t
  left join signatures s on s.tx_id = t.id
  group by t.id;

-- Pending approvals: transactions waiting for more signatures.
create view pending_txs as
  select * from tx_summary
  where status in ('proposed', 'executing')
  and not ready;

-- ============================================================
-- RLS policies
-- ============================================================
-- Public read, authenticated write. Adjust per app needs.

alter table wallets enable row level security;
alter table owners enable row level security;
alter table transactions enable row level security;
alter table signatures enable row level security;
alter table approvals enable row level security;
alter table config_log enable row level security;

-- Public read and write — all data is public (blockchain mirrors).
-- Writes are primarily routed through security definer functions,
-- but direct access is allowed for flexibility.
create policy wallets_all on wallets for all using (true) with check (true);
create policy owners_all on owners for all using (true) with check (true);
create policy tx_all on transactions for all using (true) with check (true);
create policy sigs_all on signatures for all using (true) with check (true);
create policy approvals_all on approvals for all using (true) with check (true);
create policy config_all on config_log for all using (true) with check (true);

-- ============================================================
-- Functions
-- ============================================================

-- Register a new wallet from factory deployment.
create or replace function register_wallet(
  p_chain_id int,
  p_address text,
  p_deployer text,
  p_salt numeric,
  p_owners text[],
  p_threshold smallint,
  p_delay int,
  p_executor text,
  p_block bigint,
  p_tx text
) returns uuid as $$
declare
  w_id uuid;
  i int;
begin
  insert into wallets (chain_id, address, deployer, salt, threshold, owner_count, delay, executor, created_block, created_tx)
  values (p_chain_id, p_address, p_deployer, p_salt, p_threshold, array_length(p_owners, 1), p_delay, p_executor, p_block, p_tx)
  returning id into w_id;

  for i in 1..array_length(p_owners, 1) loop
    insert into owners (wallet_id, address, position, added_block)
    values (w_id, p_owners[i], i - 1, p_block);
  end loop;

  insert into config_log (wallet_id, event, block_number, tx_hash, threshold, delay, executor, owner_count)
  values (w_id, 'init', p_block, p_tx, p_threshold, p_delay, p_executor, array_length(p_owners, 1));

  return w_id;
end;
$$ language plpgsql security definer;

-- Propose a transaction: compute hash off-chain, store with metadata.
create or replace function propose_tx(
  p_wallet_id uuid,
  p_chain_id int,
  p_nonce int,
  p_target text,
  p_value numeric,
  p_call_data text,
  p_tx_hash text,
  p_threshold smallint,
  p_proposed_by text,
  p_description text default null
) returns uuid as $$
declare
  t_id uuid;
begin
  insert into transactions (wallet_id, chain_id, nonce, target, value, call_data, tx_hash, threshold, proposed_by, description)
  values (p_wallet_id, p_chain_id, p_nonce, p_target, p_value, p_call_data, p_tx_hash, p_threshold, p_proposed_by, p_description)
  returning id into t_id;

  return t_id;
end;
$$ language plpgsql security definer;

-- Add a signature to a transaction. Returns current sig count.
create or replace function add_signature(
  p_tx_id uuid,
  p_signer text,
  p_signature text,
  p_sig_type sig_type default 'ecdsa'
) returns int as $$
declare
  cnt int;
begin
  insert into signatures (tx_id, signer, sig_type, signature)
  values (p_tx_id, p_signer, p_sig_type, p_signature)
  on conflict (tx_id, signer) do update set
    signature = excluded.signature,
    sig_type = excluded.sig_type,
    signed_at = now();

  select count(*) into cnt from signatures where tx_id = p_tx_id;
  return cnt;
end;
$$ language plpgsql security definer;

-- Mark transaction as executed.
create or replace function mark_executed(
  p_tx_id uuid,
  p_block bigint,
  p_execution_tx text
) returns void as $$
begin
  update transactions
  set status = 'executed', executed_at = now(), executed_block = p_block, execution_tx = p_execution_tx
  where id = p_tx_id;

  -- Bump wallet nonce
  update wallets set nonce = nonce + 1
  where id = (select wallet_id from transactions where id = p_tx_id);
end;
$$ language plpgsql security definer;

-- Mark transaction as queued with ETA.
create or replace function mark_queued(
  p_tx_id uuid,
  p_eta bigint,
  p_block bigint
) returns void as $$
begin
  update transactions
  set status = 'queued', eta = p_eta, queued_at = now(), queued_block = p_block
  where id = p_tx_id;
end;
$$ language plpgsql security definer;

-- Cancel a queued transaction (executor only — enforce in app layer).
create or replace function cancel_tx(
  p_tx_id uuid,
  p_cancelled_by text
) returns void as $$
begin
  update transactions
  set status = 'cancelled', cancelled_at = now(), cancelled_by = p_cancelled_by
  where id = p_tx_id and status = 'queued';
end;
$$ language plpgsql security definer;
