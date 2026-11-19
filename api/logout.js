// [로그아웃] 서버의 세션 행을 지우고 쿠키를 만료시킨다.
import { json, onlyMethod, sameOrigin, endSession } from '../lib/auth.js';

export default async function handler(req, res) {
  if (!onlyMethod(req, res, 'POST') || !sameOrigin(req, res)) return;
  await endSession(req, res);
  json(res, 200, { loggedOut: true });
}
