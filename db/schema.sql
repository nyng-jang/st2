-- 과제 8 패스키 인증용 스키마. 같은 Supabase 프로젝트의 다른 앱과 섞이지 않도록 passkey 스키마에만 둔다.
-- 앱은 passkey_app 역할로 접속하고, 이 역할은 passkey 스키마에만 권한이 있다.
create schema if not exists passkey;

-- 가상 계정. 미리 넣어 둔 계정만 쓸 수 있다(누구나 계정을 새로 만들 수는 없다).
create table if not exists passkey.accounts (
  id text primary key,
  display_name text not null
);

-- 등록된 패스키. 공개키와 공개 메타데이터만 저장한다. 개인키는 인증기 밖으로 나오지 않는다.
create table if not exists passkey.credentials (
  id text primary key,                         -- 자격 증명 ID (base64url)
  account_id text not null references passkey.accounts(id),
  public_key bytea not null,                   -- COSE 형식 공개키
  counter bigint not null default 0,
  transports text[] not null default '{}',
  device_type text,                            -- singleDevice / multiDevice
  backed_up boolean,
  name text not null,                          -- 사람이 알아볼 이름
  created_at timestamptz not null default now(),
  last_used_at timestamptz
);
create index if not exists credentials_account_idx on passkey.credentials(account_id);

-- 일회용 챌린지. 검증할 때 delete ... returning 으로 지워서 한 번만 쓸 수 있다.
create table if not exists passkey.challenges (
  challenge text primary key,                  -- base64url
  purpose text not null check (purpose in ('register', 'login')),
  account_id text references passkey.accounts(id),
  via_session boolean not null default false,  -- 로그인한 상태에서 추가 등록하는 경우
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

-- 서버 세션. 쿠키에는 무작위 토큰, DB에는 그 SHA-256 해시만 저장한다.
create table if not exists passkey.sessions (
  token_hash text primary key,
  account_id text not null references passkey.accounts(id),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);

-- 비공개 자료. 모두 직접 지어낸 가상 내용이다.
create table if not exists passkey.private_items (
  id serial primary key,
  account_id text not null references passkey.accounts(id),
  kind text not null,
  title text not null,
  body text not null
);
create index if not exists private_items_account_idx on passkey.private_items(account_id);

-- Supabase의 공개 API(anon, authenticated)에서는 이 스키마에 접근하지 못하게 막는다.
revoke all on schema passkey from public;
alter table passkey.accounts enable row level security;
alter table passkey.credentials enable row level security;
alter table passkey.challenges enable row level security;
alter table passkey.sessions enable row level security;
alter table passkey.private_items enable row level security;
