// [비공개 자료 조회] 세션의 계정 자료만 돌려준다.
// 주소(?account=)나 본문에 다른 계정을 적어도 무시한다. 기준은 오직 세션이다.
import { sql } from '../lib/db.js';
import { json, requireAccount } from '../lib/auth.js';

export default async function handler(req, res) {
  const account = await requireAccount(req, res);
  if (!account) return;
  const items = await sql`
    select id, kind, title, body from private_items where account_id = ${account} order by id`;
  const requested = req.query?.account ?? req.body?.account ?? null;
  json(res, 200, { account, requestedAccount: requested, count: items.length, items });
}
