-- WANTED CONTROL — Supabase setup
-- Run this file once in Supabase SQL Editor.
-- Initial administrator password is supplied separately. Only its bcrypt hash is stored here.

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;
create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

create table if not exists private.admin_users (
  username text primary key,
  password_hash text not null,
  created_at timestamptz not null default now()
);
create table if not exists private.admin_sessions (
  token_hash text primary key,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);
create table if not exists private.login_guard (
  username text primary key,
  attempts integer not null default 0,
  window_started_at timestamptz not null default now(),
  locked_until timestamptz
);

create table if not exists public.wanted_widgets (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 60),
  display_token text not null unique,
  level smallint not null default 0 check (level between 0 and 5),
  settings jsonb not null default '{
    "scale":1,"gap":5,"activeColor":"#f2f3ef","inactiveColor":"#303538",
    "outlineColor":"#111416","glow":true,"animations":true,"finalFlash":true,
    "canvasWidth":600,"canvasHeight":120,"alignment":"center"
  }'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.wanted_widgets enable row level security;
revoke all on public.wanted_widgets from public, anon, authenticated;
revoke all on all tables in schema private from public, anon, authenticated;

-- Initial login: username cjlakc. The password itself is not present in this SQL.
insert into private.admin_users(username, password_hash)
values ('cjlakc', '$2a$12$lD2Kx1FZ5ngkY/E8FLN8Fe7VlPBf8UxNVs1imcau.JPf6bLq9LzQe')
on conflict (username) do nothing;

create or replace function private.is_admin_session(p_token text)
returns boolean language sql stable security definer set search_path = ''
as $$
  select p_token is not null and exists (
    select 1 from private.admin_sessions s
    where s.token_hash = encode(extensions.digest(convert_to(p_token,'UTF8'),'sha256'),'hex')
      and s.expires_at > now()
  );
$$;

create or replace function private.assert_admin(p_token text)
returns void language plpgsql security definer set search_path = ''
as $$
begin
  if not private.is_admin_session(p_token) then
    raise exception 'Session expired or unauthorized' using errcode = '28000';
  end if;
end;
$$;

create or replace function public.admin_login(p_username text, p_password text)
returns text language plpgsql security definer set search_path = ''
as $$
declare
  v_hash text;
  v_guard private.login_guard%rowtype;
  v_token text;
  v_user text := lower(trim(coalesce(p_username,'')));
begin
  if v_user <> 'cjlakc' or p_password is null or char_length(p_password) > 256 then
    return null;
  end if;
  insert into private.login_guard(username) values (v_user) on conflict do nothing;
  select * into v_guard from private.login_guard where username = v_user for update;
  if v_guard.locked_until is not null and v_guard.locked_until > now() then return null; end if;

  select password_hash into v_hash from private.admin_users where username = v_user;
  if v_hash is not null and extensions.crypt(p_password, v_hash) = v_hash then
    update private.login_guard set attempts=0, window_started_at=now(), locked_until=null where username=v_user;
    v_token := encode(extensions.gen_random_bytes(32),'hex');
    insert into private.admin_sessions(token_hash, expires_at)
      values (encode(extensions.digest(convert_to(v_token,'UTF8'),'sha256'),'hex'), now()+interval '21 days');
    return v_token;
  end if;

  if v_guard.window_started_at < now()-interval '15 minutes' then
    update private.login_guard set attempts=1,window_started_at=now(),locked_until=null where username=v_user;
  elsif v_guard.attempts+1 >= 7 then
    update private.login_guard set attempts=v_guard.attempts+1,locked_until=now()+interval '15 minutes' where username=v_user;
  else
    update private.login_guard set attempts=v_guard.attempts+1 where username=v_user;
  end if;
  return null;
end;
$$;

create or replace function public.admin_validate_session(p_session_token text)
returns boolean language sql security definer set search_path = ''
as $$ select private.is_admin_session(p_session_token); $$;

create or replace function public.admin_logout(p_session_token text)
returns boolean language plpgsql security definer set search_path = ''
as $$
begin
  delete from private.admin_sessions
  where token_hash=encode(extensions.digest(convert_to(coalesce(p_session_token,''),'UTF8'),'sha256'),'hex');
  return true;
end;
$$;

create or replace function public.admin_change_password(p_session_token text,p_current_password text,p_new_password text)
returns boolean language plpgsql security definer set search_path = ''
as $$
declare v_hash text;
begin
  perform private.assert_admin(p_session_token);
  if p_new_password is null or char_length(p_new_password)<16 or char_length(p_new_password)>256 then
    raise exception 'New password must contain at least 16 characters' using errcode='22023';
  end if;
  select password_hash into v_hash from private.admin_users where username='cjlakc';
  if v_hash is null or extensions.crypt(p_current_password,v_hash)<>v_hash then
    raise exception 'Current password is incorrect' using errcode='28000';
  end if;
  update private.admin_users set password_hash=extensions.crypt(p_new_password,extensions.gen_salt('bf',12)) where username='cjlakc';
  delete from private.admin_sessions;
  return true;
end;
$$;

create or replace function public.admin_list_widgets(p_session_token text)
returns jsonb language plpgsql security definer set search_path = ''
as $$
declare v_result jsonb;
begin
  perform private.assert_admin(p_session_token);
  select coalesce(jsonb_agg(jsonb_build_object(
    'id',w.id,'name',w.name,'display_token',w.display_token,'level',w.level,
    'settings',w.settings,'created_at',w.created_at,'updated_at',w.updated_at
  ) order by w.created_at desc),'[]'::jsonb) into v_result from public.wanted_widgets w;
  return v_result;
end;
$$;

create or replace function public.admin_create_widget(p_session_token text,p_name text)
returns jsonb language plpgsql security definer set search_path = ''
as $$
declare v_widget public.wanted_widgets%rowtype;
begin
  perform private.assert_admin(p_session_token);
  if p_name is null or char_length(trim(p_name))<1 or char_length(trim(p_name))>60 then
    raise exception 'Widget name must contain 1 to 60 characters' using errcode='22023';
  end if;
  insert into public.wanted_widgets(name,display_token)
  values(trim(p_name),encode(extensions.gen_random_bytes(32),'hex'))
  returning * into v_widget;
  return to_jsonb(v_widget);
end;
$$;

create or replace function public.admin_get_widget(p_session_token text,p_widget_id uuid)
returns jsonb language plpgsql security definer set search_path = ''
as $$
declare v_widget public.wanted_widgets%rowtype;
begin
  perform private.assert_admin(p_session_token);
  select * into v_widget from public.wanted_widgets where id=p_widget_id;
  if not found then raise exception 'Widget not found' using errcode='P0002'; end if;
  return to_jsonb(v_widget);
end;
$$;

create or replace function public.admin_change_level(p_session_token text,p_widget_id uuid,p_action text,p_level integer default null)
returns jsonb language plpgsql security definer set search_path = ''
as $$
declare v_widget public.wanted_widgets%rowtype;
begin
  perform private.assert_admin(p_session_token);
  if p_action not in ('up','down','reset','set') then raise exception 'Unsupported action' using errcode='22023'; end if;
  if p_action='set' and (p_level is null or p_level<0 or p_level>5) then raise exception 'Level must be between 0 and 5' using errcode='22023'; end if;
  update public.wanted_widgets w set
    level=case p_action
      when 'up' then least(5,w.level+1)::smallint
      when 'down' then greatest(0,w.level-1)::smallint
      when 'reset' then 0::smallint
      when 'set' then p_level::smallint
    end,
    updated_at=clock_timestamp()
  where w.id=p_widget_id returning * into v_widget;
  if not found then raise exception 'Widget not found' using errcode='P0002'; end if;
  perform realtime.send(
    jsonb_build_object('id',v_widget.id,'name',v_widget.name,'level',v_widget.level,'settings',v_widget.settings,'updated_at',v_widget.updated_at),
    'state','wanted:'||v_widget.display_token,false
  );
  return jsonb_build_object('id',v_widget.id,'name',v_widget.name,'display_token',v_widget.display_token,
    'level',v_widget.level,'settings',v_widget.settings,'created_at',v_widget.created_at,'updated_at',v_widget.updated_at);
end;
$$;

create or replace function public.admin_save_widget(p_session_token text,p_widget_id uuid,p_name text,p_settings jsonb)
returns jsonb language plpgsql security definer set search_path = ''
as $$
declare
  v_widget public.wanted_widgets%rowtype;
  v_settings jsonb;
  v_scale numeric;
  v_gap numeric;
  v_width integer;
  v_height integer;
  v_align text;
  v_active text;
  v_inactive text;
  v_outline text;
begin
  perform private.assert_admin(p_session_token);
  if p_name is null or char_length(trim(p_name))<1 or char_length(trim(p_name))>60 then raise exception 'Invalid widget name' using errcode='22023'; end if;
  if jsonb_typeof(p_settings)<>'object' then raise exception 'Settings must be an object' using errcode='22023'; end if;

  v_scale:=greatest(0.5,least(1.8,coalesce((p_settings->>'scale')::numeric,1)));
  v_gap:=greatest(0,least(24,coalesce((p_settings->>'gap')::numeric,5)));
  v_width:=greatest(200,least(1400,coalesce((p_settings->>'canvasWidth')::integer,600)));
  v_height:=greatest(80,least(500,coalesce((p_settings->>'canvasHeight')::integer,120)));
  v_align:=coalesce(p_settings->>'alignment','center');
  v_active:=coalesce(p_settings->>'activeColor','#f2f3ef');
  v_inactive:=coalesce(p_settings->>'inactiveColor','#303538');
  v_outline:=coalesce(p_settings->>'outlineColor','#111416');
  if v_align not in ('left','center','right') then raise exception 'Invalid alignment' using errcode='22023'; end if;
  if v_active !~ '^#[0-9A-Fa-f]{6}$' or v_inactive !~ '^#[0-9A-Fa-f]{6}$' or v_outline !~ '^#[0-9A-Fa-f]{6}$' then
    raise exception 'Invalid color value' using errcode='22023';
  end if;

  v_settings:=jsonb_build_object(
    'scale',v_scale,'gap',v_gap,'activeColor',v_active,'inactiveColor',v_inactive,'outlineColor',v_outline,
    'glow',coalesce((p_settings->>'glow')::boolean,true),
    'animations',coalesce((p_settings->>'animations')::boolean,true),
    'finalFlash',coalesce((p_settings->>'finalFlash')::boolean,true),
    'canvasWidth',v_width,'canvasHeight',v_height,'alignment',v_align
  );
  update public.wanted_widgets set name=trim(p_name),settings=v_settings,updated_at=clock_timestamp()
  where id=p_widget_id returning * into v_widget;
  if not found then raise exception 'Widget not found' using errcode='P0002'; end if;
  perform realtime.send(
    jsonb_build_object('id',v_widget.id,'name',v_widget.name,'level',v_widget.level,'settings',v_widget.settings,'updated_at',v_widget.updated_at),
    'state','wanted:'||v_widget.display_token,false
  );
  return to_jsonb(v_widget);
end;
$$;

create or replace function public.admin_rotate_display_token(p_session_token text,p_widget_id uuid)
returns jsonb language plpgsql security definer set search_path = ''
as $$
declare v_widget public.wanted_widgets%rowtype;
begin
  perform private.assert_admin(p_session_token);
  update public.wanted_widgets set display_token=encode(extensions.gen_random_bytes(32),'hex'),updated_at=clock_timestamp()
  where id=p_widget_id returning * into v_widget;
  if not found then raise exception 'Widget not found' using errcode='P0002'; end if;
  return to_jsonb(v_widget);
end;
$$;

create or replace function public.admin_delete_widget(p_session_token text,p_widget_id uuid)
returns boolean language plpgsql security definer set search_path = ''
as $$
begin
  perform private.assert_admin(p_session_token);
  delete from public.wanted_widgets where id=p_widget_id;
  if not found then raise exception 'Widget not found' using errcode='P0002'; end if;
  return true;
end;
$$;

create or replace function public.get_display_state(p_display_token text)
returns jsonb language sql stable security definer set search_path = ''
as $$
  select jsonb_build_object('id',w.id,'name',w.name,'level',w.level,'settings',w.settings,'updated_at',w.updated_at)
  from public.wanted_widgets w
  where w.display_token=p_display_token and char_length(p_display_token)=64;
$$;

revoke all on function private.is_admin_session(text) from public,anon,authenticated;
revoke all on function private.assert_admin(text) from public,anon,authenticated;
revoke all on function public.admin_login(text,text) from public,anon,authenticated;
revoke all on function public.admin_validate_session(text) from public,anon,authenticated;
revoke all on function public.admin_logout(text) from public,anon,authenticated;
revoke all on function public.admin_change_password(text,text,text) from public,anon,authenticated;
revoke all on function public.admin_list_widgets(text) from public,anon,authenticated;
revoke all on function public.admin_create_widget(text,text) from public,anon,authenticated;
revoke all on function public.admin_get_widget(text,uuid) from public,anon,authenticated;
revoke all on function public.admin_change_level(text,uuid,text,integer) from public,anon,authenticated;
revoke all on function public.admin_save_widget(text,uuid,text,jsonb) from public,anon,authenticated;
revoke all on function public.admin_rotate_display_token(text,uuid) from public,anon,authenticated;
revoke all on function public.admin_delete_widget(text,uuid) from public,anon,authenticated;
revoke all on function public.get_display_state(text) from public,anon,authenticated;

grant execute on function public.admin_login(text,text) to anon,authenticated;
grant execute on function public.admin_validate_session(text) to anon,authenticated;
grant execute on function public.admin_logout(text) to anon,authenticated;
grant execute on function public.admin_change_password(text,text,text) to anon,authenticated;
grant execute on function public.admin_list_widgets(text) to anon,authenticated;
grant execute on function public.admin_create_widget(text,text) to anon,authenticated;
grant execute on function public.admin_get_widget(text,uuid) to anon,authenticated;
grant execute on function public.admin_change_level(text,uuid,text,integer) to anon,authenticated;
grant execute on function public.admin_save_widget(text,uuid,text,jsonb) to anon,authenticated;
grant execute on function public.admin_rotate_display_token(text,uuid) to anon,authenticated;
grant execute on function public.admin_delete_widget(text,uuid) to anon,authenticated;
grant execute on function public.get_display_state(text) to anon,authenticated;
