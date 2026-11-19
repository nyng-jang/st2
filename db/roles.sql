-- 앱 전용 DB 역할. 비밀번호는 저장소에 넣지 않고 Vercel 환경변수(DATABASE_URL)에만 둔다.
-- create role passkey_app login password '<Vercel 환경변수에만 보관>' noinherit;
grant usage on schema passkey to passkey_app;
grant select on passkey.accounts, passkey.private_items to passkey_app;   -- 비공개 자료는 읽기만
grant select, insert, update, delete on passkey.credentials, passkey.challenges, passkey.sessions to passkey_app;
alter role passkey_app set search_path = passkey;
alter role passkey_app bypassrls;
