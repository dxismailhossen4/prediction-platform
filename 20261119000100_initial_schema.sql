-- Prediction Platform: initial Supabase/PostgreSQL schema
-- Run this only in a NEW Supabase project or adapt it as a versioned migration.
-- This schema models paid digital information content. It does not implement
-- lottery tickets, wagering, betting, prize pools, or gambling transactions.

begin;

-- -----------------------------------------------------------------------------
-- 1. Private helper schema and enum types
-- -----------------------------------------------------------------------------
create schema if not exists private;
revoke all on schema private from public;

create type public.app_role as enum (
  'super_admin',
  'content_manager',
  'order_manager',
  'support_agent'
);

create type public.content_status as enum (
  'draft',
  'published',
  'archived'
);

create type public.order_status as enum (
  'pending',
  'paid',
  'failed',
  'cancelled',
  'refunded'
);

create type public.payment_status as enum (
  'pending',
  'succeeded',
  'failed',
  'refunded'
);

create type public.entitlement_status as enum (
  'active',
  'revoked',
  'expired'
);

-- -----------------------------------------------------------------------------
-- 2. User profiles and roles
-- -----------------------------------------------------------------------------
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default '' check (char_length(display_name) <= 120),
  country_code text check (country_code is null or country_code ~ '^[A-Z]{2}$'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.user_roles (
  user_id uuid not null references auth.users(id) on delete cascade,
  role public.app_role not null,
  created_at timestamptz not null default now(),
  primary key (user_id, role)
);

-- This function is used by RLS policies. It is placed in a non-exposed schema.
create or replace function private.has_any_role(
  p_user_id uuid,
  p_roles public.app_role[]
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.user_roles ur
    where ur.user_id = p_user_id
      and ur.role = any (p_roles)
  );
$$;

revoke all on function private.has_any_role(uuid, public.app_role[]) from public, anon;
grant usage on schema private to authenticated;
grant execute on function private.has_any_role(uuid, public.app_role[]) to authenticated;

create or replace function private.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create or replace function private.handle_new_auth_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, display_name)
  values (
    new.id,
    coalesce(new.raw_user_meta_data ->> 'display_name', '')
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

revoke all on function private.handle_new_auth_user() from public, anon, authenticated;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function private.handle_new_auth_user();

create trigger profiles_set_updated_at
  before update on public.profiles
  for each row execute function private.set_updated_at();

-- -----------------------------------------------------------------------------
-- 3. Markets and prediction types
-- -----------------------------------------------------------------------------
create table public.markets (
  id uuid primary key default gen_random_uuid(),
  country_code text not null unique check (country_code ~ '^[A-Z]{2}$'),
  name text not null,
  currency_code text not null check (currency_code ~ '^[A-Z]{3}$'),
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.prediction_types (
  id uuid primary key default gen_random_uuid(),
  code text not null unique check (code in ('3D', '4D')),
  digit_length smallint not null unique check (digit_length in (3, 4)),
  is_active boolean not null default true,
  created_at timestamptz not null default now()
);

insert into public.markets (country_code, name, currency_code)
values
  ('TH', 'Thailand', 'THB'),
  ('KW', 'Kuwait', 'KWD'),
  ('BH', 'Bahrain', 'BHD')
on conflict (country_code) do update
set name = excluded.name,
    currency_code = excluded.currency_code;

insert into public.prediction_types (code, digit_length)
values ('3D', 3), ('4D', 4)
on conflict (code) do update
set digit_length = excluded.digit_length;

create trigger markets_set_updated_at
  before update on public.markets
  for each row execute function private.set_updated_at();

-- -----------------------------------------------------------------------------
-- 4. Content catalogue
-- -----------------------------------------------------------------------------
create table public.content_items (
  id uuid primary key default gen_random_uuid(),
  slug text not null unique,
  title text not null check (char_length(title) between 1 and 180),
  description text not null default '',
  prediction_type_id uuid not null references public.prediction_types(id) on delete restrict,
  market_id uuid references public.markets(id) on delete restrict,
  price_amount numeric(12,3) not null check (price_amount >= 0),
  currency_code text not null check (currency_code ~ '^[A-Z]{3}$'),
  preview_image_path text,
  status public.content_status not null default 'draft',
  published_at timestamptz,
  expires_at timestamptz,
  sort_order integer not null default 0,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint published_content_requires_preview
    check (status <> 'published' or preview_image_path is not null),
  constraint expiry_after_publish
    check (expires_at is null or published_at is null or expires_at > published_at)
);

-- 3D posts must belong to a market. 4D can remain market-neutral until configured.
-- When a market is selected, the currency must match that market.
create or replace function private.validate_content_market_and_currency()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  v_digit_length smallint;
  v_market_currency text;
begin
  select pt.digit_length
    into v_digit_length
  from public.prediction_types pt
  where pt.id = new.prediction_type_id;

  if v_digit_length is null then
    raise exception 'Invalid prediction type';
  end if;

  if v_digit_length = 3 and new.market_id is null then
    raise exception 'A 3D content item must be assigned to a market';
  end if;

  if new.market_id is not null then
    select m.currency_code
      into v_market_currency
    from public.markets m
    where m.id = new.market_id;

    if v_market_currency is null then
      raise exception 'Invalid market';
    end if;

    if new.currency_code <> v_market_currency then
      raise exception 'Currency % does not match market currency %', new.currency_code, v_market_currency;
    end if;
  end if;

  return new;
end;
$$;

create trigger content_validate_market_currency
  before insert or update of prediction_type_id, market_id, currency_code
  on public.content_items
  for each row execute function private.validate_content_market_and_currency();

create trigger content_items_set_updated_at
  before update on public.content_items
  for each row execute function private.set_updated_at();

-- Full-size paid image paths are deliberately kept out of the public catalogue.
create table public.prediction_private_assets (
  content_id uuid primary key references public.content_items(id) on delete cascade,
  full_image_path text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create trigger private_assets_set_updated_at
  before update on public.prediction_private_assets
  for each row execute function private.set_updated_at();

-- -----------------------------------------------------------------------------
-- 5. Orders, order items, payments, and access entitlements
-- -----------------------------------------------------------------------------
create table public.orders (
  id uuid primary key default gen_random_uuid(),
  order_number text not null unique default (
    'ORD-' || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 12))
  ),
  user_id uuid not null references auth.users(id) on delete restrict,
  status public.order_status not null default 'pending',
  currency_code text not null check (currency_code ~ '^[A-Z]{3}$'),
  subtotal_amount numeric(12,3) not null check (subtotal_amount >= 0),
  total_amount numeric(12,3) not null check (total_amount >= 0),
  created_at timestamptz not null default now(),
  paid_at timestamptz,
  updated_at timestamptz not null default now(),
  constraint order_total_not_less_than_subtotal check (total_amount >= subtotal_amount)
);

create table public.order_items (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.orders(id) on delete restrict,
  content_id uuid not null references public.content_items(id) on delete restrict,
  title_snapshot text not null,
  unit_price numeric(12,3) not null check (unit_price >= 0),
  currency_code text not null check (currency_code ~ '^[A-Z]{3}$'),
  created_at timestamptz not null default now(),
  unique (order_id, content_id)
);

create table public.payments (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.orders(id) on delete restrict,
  provider text not null,
  provider_reference text,
  provider_event_id text unique,
  status public.payment_status not null default 'pending',
  amount numeric(12,3) not null check (amount >= 0),
  currency_code text not null check (currency_code ~ '^[A-Z]{3}$'),
  verified_at timestamptz,
  safe_metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (provider, provider_reference)
);

create table public.entitlements (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  content_id uuid not null references public.content_items(id) on delete restrict,
  order_item_id uuid unique references public.order_items(id) on delete restrict,
  status public.entitlement_status not null default 'active',
  starts_at timestamptz not null default now(),
  expires_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (user_id, content_id),
  constraint entitlement_expiry_after_start check (expires_at is null or expires_at > starts_at)
);

create trigger orders_set_updated_at
  before update on public.orders
  for each row execute function private.set_updated_at();

create trigger payments_set_updated_at
  before update on public.payments
  for each row execute function private.set_updated_at();

create trigger entitlements_set_updated_at
  before update on public.entitlements
  for each row execute function private.set_updated_at();

-- -----------------------------------------------------------------------------
-- 6. Notifications and audit history
-- -----------------------------------------------------------------------------
create table public.notifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  title text not null check (char_length(title) between 1 and 180),
  message text not null default '',
  data jsonb not null default '{}'::jsonb,
  read_at timestamptz,
  created_at timestamptz not null default now()
);

create table public.audit_logs (
  id bigint generated always as identity primary key,
  admin_id uuid references auth.users(id) on delete set null,
  action text not null,
  entity_table text not null,
  entity_id text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

-- -----------------------------------------------------------------------------
-- 7. Indexes
-- -----------------------------------------------------------------------------
create index content_items_status_published_idx
  on public.content_items (status, published_at desc);
create index content_items_market_type_idx
  on public.content_items (market_id, prediction_type_id, created_at desc);
create index orders_user_created_idx
  on public.orders (user_id, created_at desc);
create index order_items_order_idx
  on public.order_items (order_id);
create index order_items_content_idx
  on public.order_items (content_id);
create index payments_order_idx
  on public.payments (order_id, created_at desc);
create index entitlements_user_active_idx
  on public.entitlements (user_id, status, expires_at);
create index notifications_user_created_idx
  on public.notifications (user_id, created_at desc);
create index audit_logs_admin_created_idx
  on public.audit_logs (admin_id, created_at desc);

-- -----------------------------------------------------------------------------
-- 8. Enable RLS on every application table
-- -----------------------------------------------------------------------------
alter table public.profiles enable row level security;
alter table public.user_roles enable row level security;
alter table public.markets enable row level security;
alter table public.prediction_types enable row level security;
alter table public.content_items enable row level security;
alter table public.prediction_private_assets enable row level security;
alter table public.orders enable row level security;
alter table public.order_items enable row level security;
alter table public.payments enable row level security;
alter table public.entitlements enable row level security;
alter table public.notifications enable row level security;
alter table public.audit_logs enable row level security;

-- -----------------------------------------------------------------------------
-- 9. RLS policies: profiles and staff roles
-- -----------------------------------------------------------------------------
create policy profiles_select_self_or_staff
  on public.profiles for select to authenticated
  using (
    id = (select auth.uid())
    or (select private.has_any_role((select auth.uid()), array['super_admin','order_manager','support_agent']::public.app_role[]))
  );

create policy profiles_update_self
  on public.profiles for update to authenticated
  using (id = (select auth.uid()))
  with check (id = (select auth.uid()));

create policy user_roles_select_self_or_super_admin
  on public.user_roles for select to authenticated
  using (
    user_id = (select auth.uid())
    or (select private.has_any_role((select auth.uid()), array['super_admin']::public.app_role[]))
  );

create policy user_roles_insert_super_admin
  on public.user_roles for insert to authenticated
  with check ((select private.has_any_role((select auth.uid()), array['super_admin']::public.app_role[])));

create policy user_roles_delete_super_admin
  on public.user_roles for delete to authenticated
  using ((select private.has_any_role((select auth.uid()), array['super_admin']::public.app_role[])));

-- -----------------------------------------------------------------------------
-- 10. RLS policies: markets, types, and content catalogue
-- -----------------------------------------------------------------------------
create policy markets_public_read_active
  on public.markets for select to anon, authenticated
  using (is_active = true);

create policy markets_staff_read_all
  on public.markets for select to authenticated
  using ((select private.has_any_role((select auth.uid()), array['super_admin','content_manager','order_manager','support_agent']::public.app_role[])));

create policy markets_manage_super_admin
  on public.markets for all to authenticated
  using ((select private.has_any_role((select auth.uid()), array['super_admin']::public.app_role[])))
  with check ((select private.has_any_role((select auth.uid()), array['super_admin']::public.app_role[])));

create policy prediction_types_public_read_active
  on public.prediction_types for select to anon, authenticated
  using (is_active = true);

create policy prediction_types_staff_read_all
  on public.prediction_types for select to authenticated
  using ((select private.has_any_role((select auth.uid()), array['super_admin','content_manager','order_manager','support_agent']::public.app_role[])));

create policy prediction_types_manage_super_admin
  on public.prediction_types for all to authenticated
  using ((select private.has_any_role((select auth.uid()), array['super_admin']::public.app_role[])))
  with check ((select private.has_any_role((select auth.uid()), array['super_admin']::public.app_role[])));

create policy content_public_read_published
  on public.content_items for select to anon, authenticated
  using (
    status = 'published'
    and (published_at is null or published_at <= now())
    and (expires_at is null or expires_at > now())
  );

create policy content_staff_read_all
  on public.content_items for select to authenticated
  using ((select private.has_any_role((select auth.uid()), array['super_admin','content_manager','order_manager','support_agent']::public.app_role[])));

create policy content_manage_by_content_team
  on public.content_items for all to authenticated
  using ((select private.has_any_role((select auth.uid()), array['super_admin','content_manager']::public.app_role[])))
  with check ((select private.has_any_role((select auth.uid()), array['super_admin','content_manager']::public.app_role[])));

create policy private_assets_admin_read
  on public.prediction_private_assets for select to authenticated
  using ((select private.has_any_role((select auth.uid()), array['super_admin','content_manager']::public.app_role[])));

create policy private_assets_admin_manage
  on public.prediction_private_assets for all to authenticated
  using ((select private.has_any_role((select auth.uid()), array['super_admin','content_manager']::public.app_role[])))
  with check ((select private.has_any_role((select auth.uid()), array['super_admin','content_manager']::public.app_role[])));

-- -----------------------------------------------------------------------------
-- 11. RLS policies: customer purchase history and staff operations
-- -----------------------------------------------------------------------------
create policy orders_select_owner_or_order_staff
  on public.orders for select to authenticated
  using (
    user_id = (select auth.uid())
    or (select private.has_any_role((select auth.uid()), array['super_admin','order_manager','support_agent']::public.app_role[]))
  );

create policy order_items_select_owner_or_order_staff
  on public.order_items for select to authenticated
  using (
    exists (
      select 1 from public.orders o
      where o.id = order_items.order_id
        and (
          o.user_id = (select auth.uid())
          or (select private.has_any_role((select auth.uid()), array['super_admin','order_manager','support_agent']::public.app_role[]))
        )
    )
  );

create policy payments_select_owner_or_order_staff
  on public.payments for select to authenticated
  using (
    exists (
      select 1 from public.orders o
      where o.id = payments.order_id
        and (
          o.user_id = (select auth.uid())
          or (select private.has_any_role((select auth.uid()), array['super_admin','order_manager']::public.app_role[]))
        )
    )
  );

create policy entitlements_select_owner_or_order_staff
  on public.entitlements for select to authenticated
  using (
    user_id = (select auth.uid())
    or (select private.has_any_role((select auth.uid()), array['super_admin','order_manager','support_agent']::public.app_role[]))
  );

create policy notifications_select_owner_or_staff
  on public.notifications for select to authenticated
  using (
    user_id = (select auth.uid())
    or (user_id is null and (select private.has_any_role((select auth.uid()), array['super_admin','content_manager','order_manager','support_agent']::public.app_role[])))
    or (select private.has_any_role((select auth.uid()), array['super_admin','content_manager','order_manager','support_agent']::public.app_role[]))
  );

create policy notifications_update_own
  on public.notifications for update to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

create policy notifications_insert_staff
  on public.notifications for insert to authenticated
  with check ((select private.has_any_role((select auth.uid()), array['super_admin','content_manager']::public.app_role[])));

create policy audit_logs_select_super_admin
  on public.audit_logs for select to authenticated
  using ((select private.has_any_role((select auth.uid()), array['super_admin']::public.app_role[])));

-- -----------------------------------------------------------------------------
-- 12. Explicit table grants (RLS policies still decide which rows are visible)
-- -----------------------------------------------------------------------------
revoke all on public.profiles, public.user_roles, public.markets,
  public.prediction_types, public.content_items, public.prediction_private_assets,
  public.orders, public.order_items, public.payments, public.entitlements,
  public.notifications, public.audit_logs
from anon, authenticated;

-- Public catalogue only
 grant select on public.markets, public.prediction_types, public.content_items to anon;
 grant select on public.markets, public.prediction_types, public.content_items to authenticated;

-- Profiles: clients may read permitted rows and update only their profile fields.
grant select on public.profiles to authenticated;
grant update (display_name, country_code) on public.profiles to authenticated;

-- Roles are administered by a Super Admin through the RLS-protected table.
grant select, insert, delete on public.user_roles to authenticated;

-- Staff content-management operations.
grant insert, update, delete on public.markets, public.prediction_types to authenticated;
grant insert, update, delete on public.content_items to authenticated;
grant select, insert, update, delete on public.prediction_private_assets to authenticated;

-- Customer purchase history is read-only from clients.
grant select on public.orders, public.order_items, public.payments, public.entitlements to authenticated;

-- Notifications: customers can mark their own notifications as read; staff can create.
grant select, insert on public.notifications to authenticated;
grant update (read_at) on public.notifications to authenticated;

grant select on public.audit_logs to authenticated;

-- No client-side INSERT/UPDATE/DELETE grants are given to orders, order_items,
-- payments, or entitlements. Trusted server functions/webhooks must write them.

-- -----------------------------------------------------------------------------
-- 13. Storage buckets
-- -----------------------------------------------------------------------------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values
  ('prediction-previews', 'prediction-previews', true, 10485760, array['image/jpeg','image/png','image/webp']),
  ('prediction-full', 'prediction-full', false, 20971520, array['image/jpeg','image/png','image/webp'])
on conflict (id) do update
set public = excluded.public,
    file_size_limit = excluded.file_size_limit,
    allowed_mime_types = excluded.allowed_mime_types;

-- Public previews can be downloaded by anyone because this bucket is public.
-- Upload/update/delete remains limited to content staff.
create policy preview_image_insert_staff
  on storage.objects for insert to authenticated
  with check (
    bucket_id = 'prediction-previews'
    and (select private.has_any_role((select auth.uid()), array['super_admin','content_manager']::public.app_role[]))
  );

create policy preview_image_update_staff
  on storage.objects for update to authenticated
  using (
    bucket_id = 'prediction-previews'
    and (select private.has_any_role((select auth.uid()), array['super_admin','content_manager']::public.app_role[]))
  )
  with check (
    bucket_id = 'prediction-previews'
    and (select private.has_any_role((select auth.uid()), array['super_admin','content_manager']::public.app_role[]))
  );

create policy preview_image_delete_staff
  on storage.objects for delete to authenticated
  using (
    bucket_id = 'prediction-previews'
    and (select private.has_any_role((select auth.uid()), array['super_admin','content_manager']::public.app_role[]))
  );

-- Private full-size image access is limited to staff or users with an active
-- entitlement for the content UUID in the first folder of the object path.
-- Example path: <content-uuid>/full.webp
create policy full_image_select_entitled_or_staff
  on storage.objects for select to authenticated
  using (
    bucket_id = 'prediction-full'
    and (
      (select private.has_any_role((select auth.uid()), array['super_admin','content_manager']::public.app_role[]))
      or exists (
        select 1
        from public.entitlements e
        where e.user_id = (select auth.uid())
          and e.content_id::text = (storage.foldername(name))[1]
          and e.status = 'active'
          and e.starts_at <= now()
          and (e.expires_at is null or e.expires_at > now())
      )
    )
  );

create policy full_image_insert_staff
  on storage.objects for insert to authenticated
  with check (
    bucket_id = 'prediction-full'
    and (select private.has_any_role((select auth.uid()), array['super_admin','content_manager']::public.app_role[]))
  );

create policy full_image_update_staff
  on storage.objects for update to authenticated
  using (
    bucket_id = 'prediction-full'
    and (select private.has_any_role((select auth.uid()), array['super_admin','content_manager']::public.app_role[]))
  )
  with check (
    bucket_id = 'prediction-full'
    and (select private.has_any_role((select auth.uid()), array['super_admin','content_manager']::public.app_role[]))
  );

create policy full_image_delete_staff
  on storage.objects for delete to authenticated
  using (
    bucket_id = 'prediction-full'
    and (select private.has_any_role((select auth.uid()), array['super_admin','content_manager']::public.app_role[]))
  );

commit;

-- -----------------------------------------------------------------------------
-- 14. One-time administrator bootstrap (run separately after signing up)
-- -----------------------------------------------------------------------------
-- Replace the email with your own registered Supabase Auth email, then run:
--
-- insert into public.user_roles (user_id, role)
-- select id, 'super_admin'::public.app_role
-- from auth.users
-- where email = 'YOUR_ADMIN_EMAIL@example.com'
-- on conflict do nothing;
--
-- Never let users choose their own role during public registration.
