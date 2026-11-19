// 지금 로그인한 계정을 알려 준다. 로그인하지 않았으면 401.
import { json, requireAccount } from '../lib/auth.js';

export default async function handler(req, res) {
  const account = await requireAccount(req, res);
  if (!account) return;
  json(res, 200, { account });
}
