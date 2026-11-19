// [패스키 목록·삭제] 내 계정의 패스키만 보이고, 내 것만 지울 수 있다.
import { sql } from '../lib/db.js';
import { json, requireAccount, sameOrigin } from '../lib/auth.js';

export default async function handler(req, res) {
  const account = await requireAccount(req, res);
  if (!account) return;

  if (req.method === 'GET') {
    const rows = await sql`
      select id, name, public_key, transports, device_type, backed_up, created_at, last_used_at
      from credentials where account_id = ${account} order by created_at`;
    return json(res, 200, {
      account,
      count: rows.length,
      passkeys: rows.map((r) => ({
        id: r.id,
        name: r.name,
        publicKey: Buffer.from(r.public_key).toString('base64url'),
        transports: r.transports,
        deviceType: r.device_type,
        backedUp: r.backed_up,
        createdAt: r.created_at,
        lastUsedAt: r.last_used_at,
      })),
    });
  }

  if (req.method === 'DELETE') {
    if (!sameOrigin(req, res)) return;
    const id = String(req.query.id ?? '');
    const [cred] = await sql`select account_id from credentials where id = ${id}`;
    if (!cred) return json(res, 404, { error: 'not_found' });
    if (cred.account_id !== account) return json(res, 403, { error: 'forbidden', message: '다른 계정의 패스키는 지울 수 없어요.' });
    // 마지막 하나를 지우면 이 계정으로 다시 들어올 방법이 없어지므로 막는다.
    const deleted = await sql`
      delete from credentials
      where id = ${id} and (select count(*) from credentials where account_id = ${account}) > 1
      returning id`;
    if (deleted.length === 0) {
      return json(res, 409, { error: 'last_passkey', message: '마지막 패스키는 지울 수 없어요. 다른 패스키를 먼저 등록하세요.' });
    }
    return json(res, 200, { deleted: id });
  }

  res.setHeader('Allow', 'GET, DELETE');
  json(res, 405, { error: 'method_not_allowed' });
}
