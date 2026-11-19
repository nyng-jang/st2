// [다른 계정 자료 요청] 주소에 적은 계정이 세션의 계정과 다르면 403으로 거절한다.
import { sql } from '../../../lib/db.js';
import { json, requireAccount } from '../../../lib/auth.js';

export default async function handler(req, res) {
  const account = await requireAccount(req, res);
  if (!account) return;
  const target = String(req.query.id);
  if (target !== account) {
    return json(res, 403, { error: 'forbidden', message: '다른 계정의 비공개 자료는 볼 수 없어요.', you: account, requested: target });
  }
  const items = await sql`
    select id, kind, title, body from private_items where account_id = ${account} order by id`;
  json(res, 200, { account, count: items.length, items });
}
