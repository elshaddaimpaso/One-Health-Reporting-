-- Run once in Supabase: SQL Editor -> New query -> paste -> Run

create table if not exists reports (
  id bigint generated always as identity primary key,
  sector text not null,
  area text not null,
  hazard text not null,
  description text not null,
  urgency text not null check (urgency in ('Low','Medium','High')),
  status text not null default 'Open' check (status in ('Open','Investigating','Resolved')),
  created_at bigint not null,
  updated_at bigint not null
);
create index if not exists idx_reports_created on reports (created_at desc);
create index if not exists idx_reports_area on reports (area);
create index if not exists idx_reports_sector on reports (sector);

-- Shared rate-limit counters (serverless instances can't share memory)
create table if not exists rate_limits (
  key text primary key,
  count int not null,
  reset_at bigint not null
);

-- Block the public Supabase API from touching these tables.
-- Only this server (direct Postgres connection) can read/write.
alter table reports enable row level security;
alter table rate_limits enable row level security;
