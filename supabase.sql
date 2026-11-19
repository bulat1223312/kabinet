-- Кабинет репетитора: хранилище для кабинета ученика вне урока.
-- Выполните этот файл один раз в SQL Editor вашего проекта Supabase.
-- Таблицы закрыты от прямого доступа. Читать можно только по секретной ссылке ученика,
-- записывать может только репетитор (по ключу, который хранится в его браузере).

create table if not exists public.kab_owner (
  token    text primary key,
  key_hash text not null
);
create table if not exists public.kab_data (
  token   text not null,
  item    text not null,
  data    jsonb not null,
  updated timestamptz not null default now(),
  primary key (token, item)
);
alter table public.kab_owner enable row level security;
alter table public.kab_data  enable row level security;
revoke all on public.kab_owner from anon, authenticated;
revoke all on public.kab_data  from anon, authenticated;

create or replace function public.kab_put(p_token text, p_key text, p_item text, p_data jsonb)
returns void language plpgsql security definer set search_path = public as $$
declare
  h   text := encode(sha256(convert_to(coalesce(p_key, ''), 'UTF8')), 'hex');
  cur text;
begin
  if p_token is null or length(p_token) < 16 or length(p_token) > 80
     or p_key is null or length(p_key) < 16
     or p_item is null or length(p_item) > 80 or p_data is null then
    raise exception 'bad request';
  end if;
  select key_hash into cur from kab_owner where token = p_token;
  if cur is null then
    insert into kab_owner (token, key_hash) values (p_token, h);
  elsif cur <> h then
    raise exception 'forbidden';
  end if;
  insert into kab_data (token, item, data) values (p_token, p_item, p_data)
  on conflict (token, item) do update set data = excluded.data, updated = now();
end $$;

create or replace function public.kab_get(p_token text, p_item text)
returns jsonb language sql stable security definer set search_path = public as $$
  select data from kab_data where token = p_token and item = p_item
$$;

create or replace function public.kab_del(p_token text, p_key text, p_item text)
returns void language plpgsql security definer set search_path = public as $$
declare
  h text := encode(sha256(convert_to(coalesce(p_key, ''), 'UTF8')), 'hex');
begin
  if not exists (select 1 from kab_owner where token = p_token and key_hash = h) then
    raise exception 'forbidden';
  end if;
  if p_item is null then
    delete from kab_data  where token = p_token;
    delete from kab_owner where token = p_token;
  else
    delete from kab_data where token = p_token and item = p_item;
  end if;
end $$;

revoke all on function public.kab_put(text, text, text, jsonb) from public;
revoke all on function public.kab_get(text, text) from public;
revoke all on function public.kab_del(text, text, text) from public;
grant execute on function public.kab_put(text, text, text, jsonb) to anon, authenticated;
grant execute on function public.kab_get(text, text) to anon, authenticated;
grant execute on function public.kab_del(text, text, text) to anon, authenticated;
