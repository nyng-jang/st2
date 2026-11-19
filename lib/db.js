import postgres from 'postgres';

// Supabase 트랜잭션 풀러(6543)를 쓰므로 prepared statement를 끈다.
export const sql = postgres(process.env.DATABASE_URL, {
  prepare: false,
  max: 1,
  idle_timeout: 20,
  ssl: process.env.PGSSL === 'disable' ? false : 'require',
});
