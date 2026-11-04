-- Supabase project ของระบบพนักงาน (ปฏิทินตารางงาน + ระบบตอกบัตรในอนาคต)
-- แยกจาก project ของแอปเช็คสต็อก รองรับหลายสาขา หัวข้อเพิ่มเองได้ และข้อความหลายภาษา
-- Run this once in the Supabase Dashboard -> SQL Editor (paste the whole file, click Run).

create extension if not exists pgcrypto;

-- รหัสผ่านเก็บเป็น hash เสมอ Edge Function เรียก 2 ฟังก์ชันนี้เพื่อสร้าง/เช็ค hash
create or replace function crypt_hash(plain text)
returns text language sql as $$
  select crypt(plain, gen_salt('bf'));
$$;

create or replace function crypt_check(plain text, hash text)
returns boolean language sql as $$
  select crypt(plain, hash) = hash;
$$;

-- ค่าตั้งค่าทั่วไป (เช่น hash ของรหัสแอดมินกลาง)
create table if not exists app_settings (
  key         text primary key,
  value       jsonb not null,
  updated_at  timestamptz not null default now()
);

-- บันทึกว่าใครแก้อะไรเมื่อไหร่
create table if not exists admin_log (
  id          bigserial primary key,
  created_at  timestamptz not null default now(),
  action      text not null,
  details     jsonb not null default '{}'
);

-- สาขา
create table if not exists branches (
  id              text primary key,          -- ใช้ในลิงก์ ?branch=<id> (ภาษาอังกฤษ/ตัวเลข)
  name            text not null,             -- ชื่อที่แสดง
  sort            int not null default 0,
  admin_pin_hash  text,                      -- รหัสแอดมินของสาขา (ไม่บังคับ) แก้ได้แค่สาขานี้
  sync_sheet      boolean not null default false, -- true = เขียนลงแท็บ SCHEDULE ใน Google Sheet ด้วย
  created_at      timestamptz not null default now()
);

-- พนักงานของแต่ละสาขา (ใช้กับเวรล้างห้องน้ำ และระบบตอกบัตรในอนาคต)
create table if not exists staff (
  id          bigserial primary key,
  branch_id   text not null references branches(id) on delete cascade,
  name        text not null,                 -- ชื่อที่ใช้ในข้อความ เช่น Kla
  label       text not null default '',      -- ชื่อเต็มที่แสดงในตัวเลือก เช่น กล้า Kla
  short       text not null default '',      -- ชื่อสั้นบนปฏิทิน (ว่าง = ใช้ name)
  active      boolean not null default true,
  sort        int not null default 0,
  created_at  timestamptz not null default now(),
  unique (branch_id, name)
);

-- คำแปลกลาง ใช้ร่วมกันทุกระบบ (ปฏิทิน, ตอกบัตร)
-- key เช่น ui.cal.save (ข้อความบนหน้าเว็บ), topic.holiday.name, topic.holiday.message
-- edited: ภาษาที่คนแก้เองแล้ว เช่น {my,lo} — AI จะไม่เขียนทับภาษาเหล่านี้
create table if not exists translations (
  key         text primary key,
  th          text not null default '',
  en          text not null default '',
  my          text not null default '',
  lo          text not null default '',
  km          text not null default '',
  vi          text not null default '',
  edited      text[] not null default '{}',
  updated_at  timestamptz not null default now()
);

-- หัวข้อที่สื่อสารในปฏิทิน (ใช้ร่วมกันทุกสาขา) เพิ่ม/แก้ได้จากปุ่ม ⚙️ ในหน้าปฏิทิน
-- ชื่อ/คำสั้นบนปฏิทิน/ข้อความแจ้งทีมงาน อยู่ใน translations:
--   topic.<id>.name, topic.<id>.short, topic.<id>.message
-- kind: check  = ติ๊กว่าวันนี้มี/ไม่มี (เช่น วันหยุด)
--       person = เลือกพนักงาน 1 คน (เช่น เวรล้างห้องน้ำ) ใช้ {name} ในข้อความแทนชื่อคน
create table if not exists topics (
  id          text primary key,
  color       text not null default '#8b5cf6',
  kind        text not null default 'check' check (kind in ('check', 'person')),
  sort        int not null default 0,
  active      boolean not null default true,
  updated_at  timestamptz not null default now()
);

insert into topics (id, color, kind, sort) values
  ('holiday',     '#ef4444', 'check',  0),
  ('big_clean',   '#0ea5e9', 'check',  1),
  ('stock_check', '#f59e0b', 'check',  2),
  ('toilet_duty', '#8b5cf6', 'person', 3)
on conflict (id) do nothing;

insert into translations (key, th) values
  ('topic.holiday.name',         'วันหยุด'),
  ('topic.holiday.short',        'หยุด'),
  ('topic.holiday.message',      'วันนี้วันหยุด'),
  ('topic.big_clean.name',       'ทำความสะอาดใหญ่'),
  ('topic.big_clean.short',      'สะอาด'),
  ('topic.big_clean.message',    'วันนี้ทำความสะอาดใหญ่'),
  ('topic.stock_check.name',     'เช็คสต็อค'),
  ('topic.stock_check.short',    'สต็อค'),
  ('topic.stock_check.message',  'วันนี้คือวันเช็คสต็อค'),
  ('topic.toilet_duty.name',     'เวรล้างห้องน้ำ'),
  ('topic.toilet_duty.short',    ''),
  ('topic.toilet_duty.message',  'วันนี้คือเวรล้างห้องน้ำของ "{name}"')
on conflict (key) do nothing;

-- ปฏิทิน: หัวข้อที่มีในวันนั้นของแต่ละสาขา (หนึ่งแถวต่อหัวข้อ)
create table if not exists schedule_entries (
  branch_id   text not null references branches(id) on delete cascade,
  date        date not null,
  topic_id    text not null references topics(id) on delete cascade,
  person      text,                          -- staff.name สำหรับหัวข้อแบบ person
  updated_at  timestamptz not null default now(),
  primary key (branch_id, date, topic_id)
);
create index if not exists schedule_entries_month on schedule_entries (branch_id, date);

-- Row Level Security: deny-all for anon/authenticated (ไม่มี policy = ห้ามหมด)
-- เข้าถึงข้อมูลได้ทางเดียวคือผ่าน Edge Function "api" ที่ใช้ service-role key
alter table app_settings enable row level security;
alter table admin_log enable row level security;
alter table branches enable row level security;
alter table staff enable row level security;
alter table translations enable row level security;
alter table topics enable row level security;
alter table schedule_entries enable row level security;
