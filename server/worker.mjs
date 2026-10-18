const MB = 1_000_000;
const SESSION_MS = 7 * 24 * 60 * 60 * 1000;
const PASSWORD_ITERATIONS = 100_000;
const VIDEO_TYPES = new Set(['video/mp4', 'video/webm', 'video/quicktime']);
const encoder = new TextEncoder();

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin');
    if (origin && origin !== env.APP_ORIGIN) return new Response('Forbidden origin', { status: 403 });
    if (request.method === 'OPTIONS') return addCors(new Response(undefined, { status: 204 }), env);
    try {
      const response = await route(request, env);
      return response.status === 101 ? response : addCors(response, env);
    } catch (err) {
      const status = err.status || 500;
      return addCors(Response.json({ error: status === 500 ? 'Internal server error' : err.message }, { status }), env);
    }
  },
};

async function route(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  if (request.method === 'GET' && path === '/health') return Response.json({ app: 'Anyone', status: 'ok' });
  if (request.method === 'POST' && ['/auth/register', '/auth/login'].includes(path)) {
    const limiter = env.EVENTS.get(env.EVENTS.idFromName(`auth:${request.headers.get('CF-Connecting-IP') || 'unknown'}`));
    const allowance = await limiter.fetch('https://internal/rate', { method: 'POST' });
    if (!allowance.ok) fail(429, 'Too many attempts; try again later');
    const body = await readJson(request);
    const username = String(body.username || '').toLowerCase();
    const password = body.password;
    if (!/^[a-z][a-z0-9_]{3,31}$/.test(username) || typeof password !== 'string' || password.length < 12 || password.length > 128) {
      fail(400, 'Use a 4–32 character username and a 12–128 character password');
    }
    let user;
    if (path === '/auth/register') {
      const displayName = String(body.displayName || username).trim();
      if (!displayName || displayName.length > 80) fail(400, 'Invalid display name');
      const salt = randomHex(16);
      const hash = await hashPassword(password, salt);
      const id = crypto.randomUUID();
      const inserted = await query(env, 'INSERT INTO users(id,username,display_name,password_hash,password_salt,created_at) VALUES(?,?,?,?,?,?) ON CONFLICT(username) DO NOTHING RETURNING id', [id, username, displayName, hash, salt, Date.now()]);
      if (!inserted.length) fail(409, 'Username unavailable');
      user = { id };
    } else {
      const users = await query(env, 'SELECT * FROM users WHERE username=?', [username]);
      user = users[0];
      const hash = await hashPassword(password, user?.password_salt || '00000000000000000000000000000000');
      if (!user || !compareHex(hash, user.password_hash)) fail(401, 'Invalid username or password');
    }
    const token = randomHex(32);
    await query(env, 'INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)', [await digest(token), user.id, Date.now() + SESSION_MS]);
    return Response.json({ userId: user.id }, { headers: { 'Set-Cookie': `anyone_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_MS / 1000}` } });
  }
  const user = await authenticate(request, env);
  if (path === '/auth/logout' && request.method === 'POST') {
    await query(env, 'DELETE FROM sessions WHERE token_hash=?', [user.token_hash]);
    await env.EVENTS.get(env.EVENTS.idFromName(`user:${user.id}`)).fetch('https://internal/revoke', { method: 'POST' });
    return Response.json({ ok: true }, { headers: { 'Set-Cookie': 'anyone_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0' } });
  }
  if (path === '/me' && request.method === 'GET') return Response.json({ id: user.id, username: user.username, displayName: user.display_name, videoLimitBytes: getVideoLimit(user) });
  if (path === '/events' && request.method === 'GET') {
    if (request.headers.get('Upgrade') !== 'websocket') fail(426, 'WebSocket required');
    const headers = new Headers(request.headers);
    headers.set('X-Session-Expires', user.expires_at);
    return env.EVENTS.get(env.EVENTS.idFromName(`user:${user.id}`)).fetch(new Request(request, { headers }));
  }
  if (path === '/chats' && request.method === 'GET') {
    return Response.json(await query(env, 'SELECT c.* FROM chats c JOIN chat_members m ON m.chat_id=c.id WHERE m.user_id=? ORDER BY c.created_at DESC LIMIT 100', [user.id]));
  }
  if (path === '/chats' && request.method === 'POST') {
    const body = await readJson(request);
    if (!Array.isArray(body.usernames)) fail(400, 'Provide usernames');
    const usernames = [...new Set(body.usernames)];
    if (!Array.isArray(body.usernames) || usernames.length < 1 || usernames.length > 99 || !usernames.every((name) => typeof name === 'string')) fail(400, 'Provide 1–99 usernames');
    if (!['direct', 'group'].includes(body.kind) || (body.kind === 'direct' && usernames.length !== 1)) fail(400, 'Invalid chat kind');
    const members = await query(env, `SELECT id FROM users WHERE username IN (${usernames.map(() => '?').join(',')})`, usernames);
    if (members.length !== usernames.length || members.some((m) => m.id === user.id)) fail(400, 'Invalid members');
    const title = body.kind === 'group' ? String(body.title || '').trim() : undefined;
    if (body.kind === 'group' && (!title || title.length > 100)) fail(400, 'Group title required (up to 100 characters)');
    const id = crypto.randomUUID();
    const directKey = body.kind === 'direct' ? [user.id, members[0].id].sort().join(':') : undefined;
    if (directKey) {
      const existing = await query(env, 'SELECT id FROM chats WHERE direct_key=?', [directKey]);
      if (existing.length) return Response.json(existing[0]);
    }
    await batch(env, [
      ['INSERT INTO chats(id,kind,title,direct_key,created_by,created_at) VALUES(?,?,?,?,?,?)', [id, body.kind, title, directKey, user.id, Date.now()]],
      ...[{ id: user.id }, ...members].map((m) => ['INSERT INTO chat_members(chat_id,user_id,role) VALUES(?,?,?)', [id, m.id, m.id === user.id ? 'owner' : 'member']]),
    ]);
    return Response.json({ id }, { status: 201 });
  }
  const match = path.match(/^\/chats\/([a-f0-9-]+)\/(messages|videos)$/);
  if (match) {
    const [, chatId, resource] = match;
    await requireMembership(env, chatId, user.id);
    if (resource === 'messages' && request.method === 'GET') {
      const before = url.searchParams.get('before') || '9223372036854775807';
      if (!/^\d+$/.test(before)) fail(400, 'Invalid cursor');
      return Response.json(await query(env, 'SELECT rowid AS cursor,* FROM messages WHERE chat_id=? AND rowid < CAST(? AS INTEGER) ORDER BY rowid DESC LIMIT 50', [chatId, before]));
    }
    if (resource === 'messages' && request.method === 'POST') {
      const body = await readJson(request);
      const text = typeof body.text === 'string' ? body.text.trim() : '';
      if (text.length > 4096 || (!text && !body.attachmentId)) fail(400, 'Provide text (up to 4096 characters) or a video');
      if (body.attachmentId) {
        const owned = await query(env, 'SELECT id FROM attachments WHERE id=? AND chat_id=? AND user_id=?', [body.attachmentId, chatId, user.id]);
        if (!owned.length) fail(403, 'Invalid attachment');
      }
      const message = { id: crypto.randomUUID(), chatId, senderId: user.id, text, attachmentId: body.attachmentId, createdAt: Date.now() };
      await query(env, 'INSERT INTO messages(id,chat_id,sender_id,text,attachment_id,created_at) VALUES(?,?,?,?,?,?)', [message.id, chatId, user.id, text, body.attachmentId, message.createdAt]);
      const members = await query(env, 'SELECT user_id FROM chat_members WHERE chat_id=?', [chatId]);
      await Promise.allSettled(members.map((m) => env.EVENTS.get(env.EVENTS.idFromName(`user:${m.user_id}`)).fetch('https://internal/publish', { method: 'POST', body: JSON.stringify({ type: 'message', message }) })));
      return Response.json(message, { status: 201 });
    }
    if (resource === 'videos' && request.method === 'POST') {
      const type = request.headers.get('Content-Type');
      if (!VIDEO_TYPES.has(type)) fail(415, 'Supported video types: MP4, WebM, MOV');
      const size = Number(request.headers.get('Content-Length'));
      const limit = getVideoLimit(user);
      if (!Number.isSafeInteger(size) || size <= 0) fail(411, 'Content-Length required');
      if (size > limit) fail(413, `Video limit is ${limit / MB} MB`);
      if (!request.body) fail(400, 'Video body required');
      const id = crypto.randomUUID();
      const key = `${chatId}/${id}`;
      let received = 0;
      const stream = request.body.pipeThrough(new TransformStream({ transform(chunk, controller) {
        received += chunk.byteLength;
        if (received > limit || received > size) throw new Error('Video exceeds declared size');
        controller.enqueue(chunk);
      }, flush() {
        if (received !== size) throw new Error('Video length mismatch');
      } }));
      const fixed = new FixedLengthStream(size);
      await Promise.all([stream.pipeTo(fixed.writable), env.MEDIA.put(key, fixed.readable, { httpMetadata: { contentType: type } })]);
      try {
        await query(env, 'INSERT INTO attachments(id,chat_id,user_id,object_key,content_type,size,created_at) VALUES(?,?,?,?,?,?,?)', [id, chatId, user.id, key, type, size, Date.now()]);
      } catch (err) {
        await env.MEDIA.delete(key);
        throw err;
      }
      return Response.json({ id, size }, { status: 201 });
    }
  }
  const mediaMatch = path.match(/^\/media\/([a-f0-9-]+)$/);
  if (mediaMatch && request.method === 'GET') {
    const [attachment] = await query(env, 'SELECT * FROM attachments WHERE id=?', [mediaMatch[1]]);
    if (!attachment) fail(404, 'Not found');
    await requireMembership(env, attachment.chat_id, user.id);
    const object = await env.MEDIA.get(attachment.object_key, { range: request.headers });
    if (!object) fail(404, 'Not found');
    const headers = new Headers({ 'Content-Type': attachment.content_type, 'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff', 'Accept-Ranges': 'bytes' });
    if (object.range) {
      const offset = object.range.offset ?? Math.max(0, object.size - object.range.suffix);
      const length = object.range.length ?? Math.min(object.size, object.range.suffix);
      headers.set('Content-Range', `bytes ${offset}-${offset + length - 1}/${object.size}`);
      headers.set('Content-Length', String(length));
    } else headers.set('Content-Length', String(object.size));
    return new Response(object.body, { status: object.range ? 206 : 200, headers });
  }
  fail(404, 'Not found');
}

export class UserEvents {
  constructor(state) { this.state = state; }
  async fetch(request) {
    const path = new URL(request.url).pathname;
    if (path === '/rate') {
      const now = Date.now();
      const count = await this.state.storage.transaction(async (storage) => {
        const record = await storage.get('rate');
        const next = !record || now - record.start >= 60_000 ? { start: now, count: 1 } : { ...record, count: record.count + 1 };
        await storage.put('rate', next);
        return next.count;
      });
      return new Response(undefined, { status: count > 10 ? 429 : 204 });
    }
    if (path === '/revoke') {
      for (const socket of this.state.getWebSockets()) socket.close(1000, 'Session ended');
      return new Response(undefined, { status: 204 });
    }
    if (path === '/publish') {
      const event = await request.text();
      for (const socket of this.state.getWebSockets()) {
        if (socket.deserializeAttachment().expiresAt <= Date.now()) { socket.close(1000, 'Session expired'); continue; }
        try { socket.send(event); } catch { socket.close(); }
      }
      return new Response(undefined, { status: 204 });
    }
    if (this.state.getWebSockets().length >= 5) return new Response('Connection limit', { status: 429 });
    const pair = new WebSocketPair();
    this.state.acceptWebSocket(pair[1]);
    const expiresAt = Number(request.headers.get('X-Session-Expires'));
    pair[1].serializeAttachment({ expiresAt });
    const alarm = await this.state.storage.getAlarm();
    if (!alarm || alarm > expiresAt) await this.state.storage.setAlarm(expiresAt);
    return new Response(undefined, { status: 101, webSocket: pair[0] });
  }
  webSocketMessage(socket) { socket.close(1008, 'Receive-only connection'); }
  webSocketClose(socket, code) { socket.close(code); }
  async alarm() {
    let next = Infinity;
    for (const socket of this.state.getWebSockets()) {
      const { expiresAt } = socket.deserializeAttachment();
      if (expiresAt <= Date.now()) socket.close(1000, 'Session expired');
      else next = Math.min(next, expiresAt);
    }
    if (Number.isFinite(next)) await this.state.storage.setAlarm(next);
  }
}

function getVideoLimit(user) { return (Number(user.premium_until) > Date.now() ? 100 : 50) * MB; }
async function authenticate(request, env) {
  const token = request.headers.get('Cookie')?.match(/(?:^|;\s*)anyone_session=([a-f0-9]{64})(?:;|$)/)?.[1];
  if (!token) fail(401, 'Sign in required');
  const [user] = await query(env, 'SELECT u.*,s.token_hash,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?', [await digest(token), Date.now()]);
  if (!user) fail(401, 'Session expired');
  return user;
}
async function requireMembership(env, chatId, userId) {
  if (!(await query(env, 'SELECT 1 AS ok FROM chat_members WHERE chat_id=? AND user_id=?', [chatId, userId])).length) fail(403, 'Chat access denied');
}
async function readJson(request) {
  const reader = request.body?.getReader();
  if (!reader) fail(400, 'JSON body required');
  let text = '';
  let bytes = 0;
  const decoder = new TextDecoder();
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    if (bytes > 16_384) { await reader.cancel(); fail(413, 'Request too large'); }
    text += decoder.decode(value, { stream: true });
  }
  try { const body = JSON.parse(text + decoder.decode()); if (!body || typeof body !== 'object' || Array.isArray(body)) fail(400, 'JSON object required'); return body; } catch { fail(400, 'Invalid JSON'); }
}
async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  return toHex(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: encoder.encode(salt), iterations: PASSWORD_ITERATIONS, hash: 'SHA-256' }, key, 256));
}
async function digest(text) { return toHex(await crypto.subtle.digest('SHA-256', encoder.encode(text))); }
function randomHex(length) { return toHex(crypto.getRandomValues(new Uint8Array(length))); }
function toHex(buffer) { return Array.from(new Uint8Array(buffer), (n) => n.toString(16).padStart(2, '0')).join(''); }
function compareHex(a, b) { if (a.length !== b.length) return false; let diff = 0; for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i); return diff === 0; }
function fail(status, message) { throw Object.assign(new Error(message), { status }); }
function addCors(response, env) {
  response.headers.set('Access-Control-Allow-Origin', env.APP_ORIGIN);
  response.headers.set('Access-Control-Allow-Credentials', 'true');
  response.headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  response.headers.set('Access-Control-Allow-Headers', 'Content-Type');
  response.headers.set('Vary', 'Origin');
  response.headers.set('Cache-Control', 'no-store');
  return response;
}
async function query(env, sql, args = []) { return (await batch(env, [[sql, args]], false))[0]; }
async function batch(env, statements, transaction = true) {
  const encodeArg = (value) => value === undefined ? { type: 'null' } : typeof value === 'number' ? { type: 'integer', value: String(value) } : { type: 'text', value: String(value) };
  const sqlStatements = transaction ? [['BEGIN IMMEDIATE', []], ...statements, ['COMMIT', []]] : statements;
  const steps = sqlStatements.map(([sql, args], index) => ({
    stmt: { sql, args: args.map(encodeArg), want_rows: true },
    ...(index ? { condition: { type: 'ok', step: index - 1 } } : {}),
  }));
  if (transaction) steps.push({ stmt: { sql: 'ROLLBACK' }, condition: { type: 'not', cond: { type: 'ok', step: steps.length - 1 } } });
  const response = await fetch(`${env.TURSO_DATABASE_URL.replace(/^libsql:/, 'https:').replace(/\/$/, '')}/v2/pipeline`, {
    method: 'POST', headers: { Authorization: `Bearer ${env.TURSO_AUTH_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ requests: [{ type: 'execute', stmt: { sql: 'PRAGMA foreign_keys = ON' } }, { type: 'batch', batch: { steps } }, { type: 'close' }] }),
  });
  if (!response.ok) throw new Error('Database unavailable');
  const result = await response.json();
  if (result.results[0].type === 'error') throw new Error('Database initialization failed');
  const responseBatch = result.results[1];
  if (responseBatch.type === 'error' || responseBatch.response.result.step_errors.some(Boolean)) throw new Error('Database operation failed');
  const results = responseBatch.response.result.step_results.slice(0, sqlStatements.length);
  const rows = results.map((r) => r.rows.map((row) => Object.fromEntries(row.map((cell, i) => [r.cols[i].name, cell.type === 'null' ? undefined : cell.value]))));
  return transaction ? rows.slice(1, -1) : rows;
}
