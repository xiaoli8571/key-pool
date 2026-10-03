'use strict';
/*
 * KeyPool 自动化测试
 * 启动一个 Mock 上游（模拟 429 / 5xx / 401 / 402 / 流式），再启动 KeyPool，
 * 验证：密钥轮换、429 冷却与全池熔断、401 自动禁用、SSE 流式透传、网关鉴权、多协议。
 * 运行：node test/run.js
 */

const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');

const POOL_PORT = 18500;
const MOCK_PORT = 18501;
const POOL = `http://127.0.0.1:${POOL_PORT}`;
const MOCK = `http://127.0.0.1:${MOCK_PORT}`;

let passCount = 0;
let failCount = 0;
function ok(cond, name, extra) {
  if (cond) {
    passCount++;
    console.log(`  ✅ ${name}`);
  } else {
    failCount++;
    console.log(`  ❌ ${name}${extra ? ' — ' + extra : ''}`);
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function jfetch(url, opts) {
  const res = await fetch(url, opts);
  const text = await res.text();
  let body = null;
  try { body = JSON.parse(text); } catch { body = text; }
  return { status: res.status, headers: res.headers, body, text };
}

/* ---------------- Mock 上游 ---------------- */
function startMock() {
  const hits = { keyHits: {} }; // 记录每个 key 的请求命中次数
  const server = http.createServer(async (req, res) => {
    let raw = '';
    for await (const c of req) raw += c;
    let body = {};
    try { body = JSON.parse(raw || '{}'); } catch {}
    const auth = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '') || req.headers['x-api-key'] || '';
    const model = body.model || '';
    // 只统计"调用类"请求的命中次数；GET /models 这类列表探测不计入（模型池刷新会并发打列表）
    const isListProbe = req.method === 'GET' && /\/models$/.test(req.url.split('?')[0]);
    if (!isListProbe) hits.keyHits[auth] = (hits.keyHits[auth] || 0) + 1;
    const n = hits.keyHits[auth]; // 该 key 第 n 次被调用
    const sendJSON = (code, obj) => {
      res.writeHead(code, { 'content-type': 'application/json' });
      res.end(JSON.stringify(obj));
    };

    // 命中计数查询（测试用）
    if (req.method === 'GET' && req.url === '/__hits') return sendJSON(200, hits.keyHits);
    // 模型列表故障开关（测试模型池兜底）
    if (req.method === 'GET' && req.url.startsWith('/__modelsfail')) {
      hits.modelsFail = !req.url.includes('off=1');
      return sendJSON(200, { modelsFail: !!hits.modelsFail });
    }
    // OpenAI: /v1/models — 按密钥差异化（聚合平台常见：模型授权按 Key 下发）
    if (req.method === 'GET' && req.url === '/v1/models') {
      if (hits.modelsFail) return sendJSON(500, { error: { message: 'models endpoint temporarily down' } });
      if (!auth || auth === 'sk-dead') return sendJSON(401, { error: { message: 'Incorrect API key provided' } });
      if (auth === 'sk-poor') return sendJSON(402, { error: { message: 'You have insufficient credit balance, please top up' } });
      const base = [{ id: 'mock-model-a', object: 'model' }, { id: 'mock-model-b', object: 'model' }];
      const extra = auth === 'sk-good-a' ? [{ id: 'mock-only-in-a', object: 'model' }, { id: 'mock-tts-a', object: 'model', mode: 'tts' }] : [];
      return sendJSON(200, { object: 'list', data: base.concat(extra) });
    }
    // OpenAI: chat
    if (req.method === 'POST' && req.url === '/v1/chat/completions') {
      if (!auth) return sendJSON(401, { error: { message: 'Missing API key' } });
      if (auth === 'sk-dead') return sendJSON(401, { error: { message: 'Incorrect API key provided' } });
      if (auth === 'sk-poor') return sendJSON(402, { error: { message: 'You have insufficient credit balance, please top up' } });
      // flaky429：sk-flaky 对每个独立模型名前两次 429，之后成功（验证单密钥故障→轮换→恢复）
      if (model.startsWith('flaky429') && auth === 'sk-flaky') {
        hits.flaky429 = hits.flaky429 || {};
        hits.flaky429[model] = (hits.flaky429[model] || 0) + 1;
        if (hits.flaky429[model] <= 2) return sendJSON(429, { error: { message: 'Rate limit exceeded, too many requests' } });
      }
      // flaky500：sk-flaky 恒定 5xx（验证单密钥 5xx → 轮换）
      if (model.startsWith('flaky500') && auth === 'sk-flaky') {
        return sendJSON(500, { error: { message: 'Internal server error' } });
      }
      // ra429：sk-good-a 返回带 Retry-After 头的 429（验证网关遵循上游 Retry-After），其他 key 正常
      if (model.startsWith('ra429') && auth === 'sk-good-a') {
        res.writeHead(429, { 'content-type': 'application/json', 'retry-after': '20' });
        res.end(JSON.stringify({ error: { message: 'Slow down, retry after 20 seconds' } }));
        return;
      }
      if (model.startsWith('fail429')) return sendJSON(429, { error: { message: 'Rate limit exceeded, too many requests' } });
      if (model.startsWith('fail500')) return sendJSON(500, { error: { message: 'Internal server error' } });
      // mkonly：仅 sk-pro* 密钥支持该模型，其余密钥返回“invalid model field”（验证按模型权限轮换）
      if (model.startsWith('mkonly') && !auth.startsWith('sk-pro')) {
        return sendJSON(400, { error: { message: 'invalid model field', type: 'tierflow_error' } });
      }
      // mkall：所有密钥都不支持（验证轮换耗尽后如实返回 400 而非 502）
      if (model.startsWith('mkall')) {
        return sendJSON(400, { error: { message: 'invalid model field', type: 'tierflow_error' } });
      }
      // slow：慢速响应（80ms），用于并发占位/负载分散测试
      if (model.startsWith('slow')) {
        setTimeout(() => {
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ id: 'chatcmpl-mock', object: 'chat.completion', model, choices: [{ index: 0, message: { role: 'assistant', content: 'Hello from ' + auth }, finish_reason: 'stop' }], usage: { prompt_tokens: 9, completion_tokens: 4 } }));
        }, 80);
        return;
      }
      if (body.stream) {
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        const chunks = ['你', '好', '，', '世', '界'];
        let i = 0;
        const timer = setInterval(() => {
          if (i < chunks.length) {
            res.write(`data: ${JSON.stringify({ id: 'chatcmpl-mock', choices: [{ delta: { content: chunks[i++] } }] })}\n\n`);
          } else {
            clearInterval(timer);
            res.write(`data: ${JSON.stringify({ id: 'chatcmpl-mock', choices: [{ delta: {} }], usage: { prompt_tokens: 12, completion_tokens: 5 } })}\n\n`);
            res.write('data: [DONE]\n\n');
            res.end();
          }
        }, 15);
        req.on('close', () => clearInterval(timer));
        return;
      }
      return sendJSON(200, {
        id: 'chatcmpl-mock',
        object: 'chat.completion',
        model: model || 'mock-model-a',
        choices: [{ index: 0, message: { role: 'assistant', content: 'Hello from ' + auth }, finish_reason: 'stop' }],
        usage: { prompt_tokens: 9, completion_tokens: 4 },
      });
    }
    // Anthropic: /v1/messages
    if (req.method === 'POST' && req.url === '/v1/messages') {
      if (!req.headers['x-api-key']) return sendJSON(401, { error: { message: 'missing x-api-key' } });
      if (req.headers['x-api-key'] === 'sk-ant-dead') return sendJSON(401, { type: 'error', error: { type: 'authentication_error', message: 'invalid x-api-key' } });
      return sendJSON(200, {
        id: 'msg-mock',
        type: 'message',
        role: 'assistant',
        model: model,
        content: [{ type: 'text', text: 'Anthropic hello from ' + req.headers['x-api-key'] }],
        usage: { input_tokens: 7, output_tokens: 3 },
      });
    }
    sendJSON(404, { error: { message: 'mock upstream: not found ' + req.url } });
  });
  server.hits = hits;
  return new Promise((resolve) => server.listen(MOCK_PORT, '127.0.0.1', () => resolve(server)));
}

/* ---------------- KeyPool 子进程 ---------------- */
function startPool(dataDir) {
  const child = spawn(process.execPath, [path.join(__dirname, '..', 'server.js'), '--port', String(POOL_PORT)], {
    cwd: path.join(__dirname, '..'),
    env: Object.assign({}, process.env, { KEYPOOL_DATA_DIR: dataDir }),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (d) => process.stdout.write('  [pool] ' + d.toString()));
  child.stderr.on('data', (d) => process.stdout.write('  [pool:err] ' + d.toString()));
  return child;
}

async function waitHealthy() {
  for (let i = 0; i < 100; i++) {
    try {
      const r = await fetch(POOL + '/health');
      if (r.ok) return true;
    } catch {}
    await sleep(100);
  }
  return false;
}

/* ---------------- 主流程 ---------------- */
async function main() {
  const dataDir = path.join(os.tmpdir(), 'keypool-test-' + Date.now());
  fs.mkdirSync(dataDir, { recursive: true });

  const mock = await startMock();
  const pool = startPool(dataDir);
  try {
    console.log('— 启动 —');
    ok(await waitHealthy(), 'KeyPool 服务健康检查通过');

    console.log('— 管理后台 —');
    let r = await jfetch(POOL + '/admin/api/overview');
    ok(r.status === 401 && r.body.error.code === 'setup_required', '未初始化时要求设置密码', JSON.stringify(r.body));
    r = await jfetch(POOL + '/admin/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ password: 'test123456' }) });
    ok(r.status === 200 && r.body.token, '设置管理密码并获取 token');
    const token = r.body.token;
    const ah = { 'content-type': 'application/json', 'x-admin-token': token };

    const page = await fetch(POOL + '/admin');
    ok(page.status === 200 && (page.headers.get('content-type') || '').includes('text/html'), '管理界面页面可访问');

    console.log('— 渠道与密钥 —');
    r = await jfetch(POOL + '/admin/api/targets', { method: 'POST', headers: ah, body: JSON.stringify({ name: 'MockOpenAI', baseUrl: MOCK, type: 'openai' }) });
    ok(r.status === 200 && r.body.target.id, '创建 OpenAI 兼容渠道');
    const t1 = r.body.target.id;

    r = await jfetch(POOL + `/admin/api/targets/${t1}/keys`, { method: 'POST', headers: ah, body: JSON.stringify({ keys: 'sk-good-a\nsk-good-b|账号B\nsk-dead\nsk-poor|欠费号\nsk-flaky|限流号' }) });
    ok(r.status === 200 && r.body.added === 5, '批量导入 5 个密钥（含备注解析）', `added=${r.body && r.body.added}`);

    const tList = (await jfetch(POOL + '/admin/api/targets', { headers: ah })).body.targets;
    const t1keys = tList.find((x) => x.id === t1).keys;
    const kid = (name) => t1keys.find((k) => k.key === name).id;
    ok(t1keys.find((k) => k.key === 'sk-good-b').note === '账号B', '密钥备注解析正确');

    console.log('— 基础转发 —');
    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model: 'mock-model-a', messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 200 && r.body.choices && String(r.body.choices[0].message.content).includes('sk-'), '请求转发成功并返回上游内容', JSON.stringify(r.body).slice(0, 120));
    ok(/sk-\*{4}/.test(r.headers.get('x-keypool-key') || ''), '响应头标记实际使用的密钥（打码）', r.headers.get('x-keypool-key'));

    console.log('— 并发轮换（负载分散） —');
    // 专用干净渠道（4 个健康密钥 + 上游 80ms 慢响应，禁用含失败规则的 t1 避免级联干扰）
    r = await jfetch(POOL + '/admin/api/targets', { method: 'POST', headers: ah, body: JSON.stringify({ name: 'MockSpread', type: 'openai', baseUrl: MOCK + '/v1' }) });
    const tSpread = r.body.target.id;
    await jfetch(POOL + `/admin/api/targets/${tSpread}/keys`, { method: 'POST', headers: ah, body: JSON.stringify({ keys: 'sk-s1\nsk-s2\nsk-s3\nsk-s4' }) });
    await jfetch(POOL + `/admin/api/targets/${t1}`, { method: 'PUT', headers: ah, body: JSON.stringify({ enabled: false }) });
    const conc = await Promise.all(
      Array.from({ length: 4 }, () =>
        jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model: 'slow-a', messages: [{ role: 'user', content: 'hi' }] }) })
      )
    );
    const usedKeys = conc.map((x) => (x.body && x.body.choices ? String(x.body.choices[0].message.content).replace('Hello from ', '') : '?'));
    const distinctKeys = new Set(usedKeys).size;
    ok(conc.every((x) => x.status === 200) && distinctKeys >= 3, '并发请求自动分散到多个密钥', `keys=[${usedKeys.join(',')}] distinct=${distinctKeys}`);
    await jfetch(POOL + `/admin/api/targets/${tSpread}`, { method: 'DELETE', headers: ah });
    await jfetch(POOL + `/admin/api/targets/${t1}`, { method: 'PUT', headers: ah, body: JSON.stringify({ enabled: true }) });

    console.log('— 单密钥 429 → 自动轮换（优先级策略） —');
    // 设为优先级策略：flaky(90) > dead(80) > poor(70) > good-a(10) > good-b(5)
    await jfetch(POOL + '/admin/api/settings', { method: 'PUT', headers: ah, body: JSON.stringify({ rotationStrategy: 'priority' }) });
    await jfetch(POOL + `/admin/api/targets/${t1}/keys/${kid('sk-flaky')}`, { method: 'PATCH', headers: ah, body: JSON.stringify({ priority: 90 }) });
    await jfetch(POOL + `/admin/api/targets/${t1}/keys/${kid('sk-dead')}`, { method: 'PATCH', headers: ah, body: JSON.stringify({ priority: 80 }) });
    await jfetch(POOL + `/admin/api/targets/${t1}/keys/${kid('sk-poor')}`, { method: 'PATCH', headers: ah, body: JSON.stringify({ priority: 70 }) });
    await jfetch(POOL + `/admin/api/targets/${t1}/keys/${kid('sk-good-a')}`, { method: 'PATCH', headers: ah, body: JSON.stringify({ priority: 10 }) });
    await jfetch(POOL + `/admin/api/targets/${t1}/keys/${kid('sk-good-b')}`, { method: 'PATCH', headers: ah, body: JSON.stringify({ priority: 5 }) });

    // 请求 1：flaky 429(第1次) → dead 401 禁用 → poor 402 冷却 → good-a 成功
    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model: 'flaky429-a', messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 200 && String(r.body.choices[0].message.content).includes('sk-good-a'), '429/401/402 密钥被跳过，落到 good-a', `status=${r.status} key=${r.headers.get('x-keypool-key')}`);

    // 请求 2：flaky 429(第2次，冷却更久) → good-a 成功
    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model: 'flaky429-b', messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 200 && String(r.body.choices[0].message.content).includes('sk-good-a'), '冷却中的 flaky 不再被选中', `key=${r.headers.get('x-keypool-key')}`);

    // 状态断言
    let st = (await jfetch(POOL + '/admin/api/keystates', { headers: ah })).body.states;
    const deadSt = st.find((x) => x.keyId === kid('sk-dead'));
    const poorSt = st.find((x) => x.keyId === kid('sk-poor'));
    const flakySt = st.find((x) => x.keyId === kid('sk-flaky'));
    ok(deadSt.status === 'disabled' && deadSt.lastStatus === 401, '401 密钥已自动禁用', JSON.stringify(deadSt));
    ok(poorSt.status === 'cooling' && poorSt.lastStatus === 402, '欠费(402)密钥进入长冷却', JSON.stringify({ s: poorSt.status, l: poorSt.lastStatus }));
    ok(flakySt.status === 'cooling' && flakySt.fail >= 1 && flakySt.coolingInSec >= 7, '429 密钥进入指数退避冷却（首次 8s）', JSON.stringify({ s: flakySt.status, f: flakySt.fail, c: flakySt.coolingInSec }));

    // 遵循上游 Retry-After：good-a 收到 429 + Retry-After: 20 → 冷却 ≈20s（而非指数 8s），轮换到 good-b
    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model: 'ra429-x', messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 200 && String(r.body.choices[0].message.content).includes('sk-good-b'), '带 Retry-After 的 429 后轮换到 good-b 成功', `key=${r.headers.get('x-keypool-key')}`);
    st = (await jfetch(POOL + '/admin/api/keystates', { headers: ah })).body.states;
    const goodASt = st.find((x) => x.keyId === kid('sk-good-a'));
    ok(goodASt.status === 'cooling' && goodASt.coolingInSec >= 15 && goodASt.coolingInSec <= 22, '遵循上游 Retry-After（冷却≈20s 而非指数 8s）', JSON.stringify({ s: goodASt.status, c: goodASt.coolingInSec }));

    console.log('— 全池熔断 —');
    // 将 good-a/good-b 也调到高优先级并同时用 fail429 模型打挂 → 全部失败 → 502
    await jfetch(POOL + `/admin/api/targets/${t1}/keys/${kid('sk-good-a')}`, { method: 'PATCH', headers: ah, body: JSON.stringify({ priority: 60 }) });
    await jfetch(POOL + `/admin/api/targets/${t1}/keys/${kid('sk-good-b')}`, { method: 'PATCH', headers: ah, body: JSON.stringify({ priority: 55 }) });
    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model: 'fail429-all', messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 502 && r.body.error.code === 'all_keys_failed', '所有可用密钥失败后返回 502', `status=${r.status}`);
    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model: 'mock-model-a', messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 429 && r.body.error.code === 'all_keys_cooling' && r.headers.get('retry-after'), '全池冷却时返回 429 + Retry-After', `status=${r.status}`);

    console.log('— 冷却恢复 —');
    // 启用/禁用重置冷却：重新启用 good-a
    await jfetch(POOL + `/admin/api/targets/${t1}/keys/${kid('sk-good-a')}`, { method: 'PATCH', headers: ah, body: JSON.stringify({ enabled: true }) });
    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model: 'mock-model-a', messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 200 && String(r.body.choices[0].message.content).includes('sk-good-a'), '重置冷却后密钥恢复服务', `key=${r.headers.get('x-keypool-key')}`);

    console.log('— 冷却到期自动恢复（不做任何手动操作） —');
    // 回归 v1.3.0 缺陷：冷却到期后 status 卡在 'cooling'，密钥被永久排除出轮换池（只能手动重启用）。
    // 用 1s 冷却基数快速验证：触发 429 → 等 1.6s → 密钥应自动回到 'ok' 并被再次选中。
    await jfetch(POOL + '/admin/api/settings', { method: 'PUT', headers: ah, body: JSON.stringify({ rateCooldownSeconds: 1 }) });
    await jfetch(POOL + `/admin/api/targets/${t1}/keys/${kid('sk-good-b')}`, { method: 'PATCH', headers: ah, body: JSON.stringify({ enabled: true }) });
    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model: 'fail429-auto', messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 502, 'fail429 请求触发全部可用密钥冷却（502）', `status=${r.status}`);
    await sleep(1600);
    st = (await jfetch(POOL + '/admin/api/keystates', { headers: ah })).body.states;
    const autoB = st.find((x) => x.keyId === kid('sk-good-b'));
    const autoA = st.find((x) => x.keyId === kid('sk-good-a'));
    ok(autoB.status === 'ok' && autoA.status === 'ok', '冷却到期后密钥状态自动复位为 ok（未手动重启用）', JSON.stringify({ b: autoB.status, a: autoA.status }));
    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model: 'mock-model-a', messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 200, '自动恢复后请求正常成功（密钥重回轮换池）', `status=${r.status}`);
    await jfetch(POOL + '/admin/api/settings', { method: 'PUT', headers: ah, body: JSON.stringify({ rateCooldownSeconds: 8 }) });

    console.log('— 5xx 短冷却轮换 —');
    // 重置 flaky 冷却（重新启用即重置），flaky 优先级最高 → 先试 flaky(500) → 轮换到 good-a 成功
    await jfetch(POOL + `/admin/api/targets/${t1}/keys/${kid('sk-flaky')}`, { method: 'PATCH', headers: ah, body: JSON.stringify({ enabled: true }) });
    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model: 'flaky500-x', messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 200 && String(r.body.choices[0].message.content).includes('sk-good-a'), '5xx 自动轮换到下一个密钥成功', `status=${r.status} key=${r.headers.get('x-keypool-key')} body=${JSON.stringify(r.body).slice(0, 120)}`);
    st = (await jfetch(POOL + '/admin/api/keystates', { headers: ah })).body.states;
    const flaky500 = st.find((x) => x.keyId === kid('sk-flaky'));
    ok(flaky500.status === 'cooling' && flaky500.lastStatus === 500, '5xx 密钥进入短冷却', JSON.stringify({ s: flaky500.status, l: flaky500.lastStatus }));

    console.log('— 流式（SSE）—');
    // 重置 good-a 冷却与统计，确保流式 usage 单独可验证
    await jfetch(POOL + `/admin/api/targets/${t1}/keys/${kid('sk-good-a')}`, { method: 'PATCH', headers: ah, body: JSON.stringify({ enabled: true, resetStats: true }) });
    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model: 'mock-model-a', stream: true, messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 200 && r.text.includes('data:') && r.text.includes('chatcmpl-mock') && r.text.includes('[DONE]'), 'SSE 流式透传完整', `status=${r.status} len=${r.text.length}`);
    st = (await jfetch(POOL + '/admin/api/keystates', { headers: ah })).body.states;
    ok(st.some((x) => x.promptTokens >= 12 && x.completionTokens >= 5), '流式 usage 统计被捕获', JSON.stringify(st.map((x) => [x.promptTokens, x.completionTokens])));

    console.log('— Anthropic 协议 —');
    r = await jfetch(POOL + '/admin/api/targets', { method: 'POST', headers: ah, body: JSON.stringify({ name: 'MockAnthropic', baseUrl: MOCK, type: 'anthropic' }) });
    const t2 = r.body.target.id;
    await jfetch(POOL + `/admin/api/targets/${t2}/keys`, { method: 'POST', headers: ah, body: JSON.stringify({ keys: 'sk-ant-dead|坏号\nsk-ant-good|好号' }) });
    const t2keys = (await jfetch(POOL + '/admin/api/targets', { headers: ah })).body.targets.find((x) => x.id === t2).keys;
    const antDeadKid = t2keys.find((k) => k.key === 'sk-ant-dead').id;
    await jfetch(POOL + `/admin/api/targets/${t2}/keys/${antDeadKid}`, { method: 'PATCH', headers: ah, body: JSON.stringify({ priority: 10 }) });
    await jfetch(POOL + `/admin/api/targets/${t2}/keys/${t2keys.find((k) => k.key === 'sk-ant-good').id}`, { method: 'PATCH', headers: ah, body: JSON.stringify({ priority: 1 }) });
    r = await jfetch(POOL + '/v1/messages', { method: 'POST', headers: { 'content-type': 'application/json', 'anthropic-version': '2023-06-01' }, body: JSON.stringify({ model: 'claude-mock', max_tokens: 32, messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 200 && r.body.content && String(r.body.content[0].text).includes('sk-ant-good'), 'Anthropic 请求自动跳过 401 密钥落到好号', JSON.stringify(r.body).slice(0, 150));
    st = (await jfetch(POOL + '/admin/api/keystates', { headers: ah })).body.states;
    const antDead = st.find((x) => x.keyId === antDeadKid);
    ok(antDead && antDead.status === 'disabled', '401 Anthropic 密钥已被自动禁用', JSON.stringify(antDead));

    console.log('— 网关鉴权 —');
    // 恢复 good-a/good-b 可用
    await jfetch(POOL + `/admin/api/targets/${t1}/keys/${kid('sk-good-a')}`, { method: 'PATCH', headers: ah, body: JSON.stringify({ enabled: true }) });
    await jfetch(POOL + `/admin/api/targets/${t1}/keys/${kid('sk-good-b')}`, { method: 'PATCH', headers: ah, body: JSON.stringify({ enabled: true }) });
    r = await jfetch(POOL + '/v1/models');
    ok(r.status === 200 && Array.isArray(r.body.data) && r.body.data.length >= 1, '/v1/models 透传成功', JSON.stringify(r.body).slice(0, 100));
    r = await jfetch(POOL + '/admin/api/settings', { method: 'PUT', headers: ah, body: JSON.stringify({ apiKeys: ['agent-secret-1'] }) });
    ok(r.status === 200, '设置网关访问密钥');
    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model: 'mock-model-a', messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 401, '无网关密钥被拒绝');
    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer agent-secret-1' }, body: JSON.stringify({ model: 'mock-model-a', messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 200, 'Authorization: Bearer 方式正常调用');
    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': 'agent-secret-1' }, body: JSON.stringify({ model: 'mock-model-a', messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 200, 'x-api-key 方式同样可用');
    r = await jfetch(POOL + '/v1/messages', { method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': 'agent-secret-1', 'anthropic-version': '2023-06-01' }, body: JSON.stringify({ model: 'claude-mock', max_tokens: 8, messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 200, 'Anthropic 协议同样受网关鉴权保护且可调用');
    await jfetch(POOL + '/admin/api/settings', { method: 'PUT', headers: ah, body: JSON.stringify({ apiKeys: [] }) });

    console.log('— 密钥测试探测 —');
    r = await jfetch(POOL + `/admin/api/targets/${t1}/test`, { method: 'POST', headers: ah, body: JSON.stringify({}) });
    const testOK = r.body.results.filter((x) => x.ok).length;
    ok(r.body.results.length === 5 && testOK === 3, '密钥连通性测试：3 好 2 坏（dead/poor 失败）', JSON.stringify(r.body.results.map((x) => [x.keyMask, x.status, x.ok])));

    // 回归：baseUrl 已含 /v1 时，探测不得拼出 /v1/v1（线上 tierflow 渠道踩过此坑）
    r = await jfetch(POOL + '/admin/api/targets', { method: 'POST', headers: ah, body: JSON.stringify({ name: 'MockV1Suffix', type: 'openai', baseUrl: MOCK + '/v1' }) });
    const tv = r.body.target.id;
    await jfetch(POOL + `/admin/api/targets/${tv}/keys`, { method: 'POST', headers: ah, body: JSON.stringify({ keys: 'sk-good-a' }) });
    r = await jfetch(POOL + `/admin/api/targets/${tv}/test`, { method: 'POST', headers: ah, body: JSON.stringify({}) });
    ok(r.status === 200 && r.body.results.length === 1 && r.body.results[0].ok, 'baseUrl 带 /v1 时探测不误拼 /v1/v1', JSON.stringify(r.body.results));
    await jfetch(POOL + `/admin/api/targets/${tv}`, { method: 'DELETE', headers: ah });

    console.log('— 模型权限轮换（按密钥×模型屏蔽，不伤密钥健康） —');
    // 渠道内密钥可用模型不同（mkonly* 仅 sk-pro* 支持）：应自动跳过不支持的密钥
    r = await jfetch(POOL + '/admin/api/targets', { method: 'POST', headers: ah, body: JSON.stringify({ name: 'MockPerms', type: 'openai', baseUrl: MOCK + '/v1' }) });
    const tPerms = r.body.target.id;
    await jfetch(POOL + `/admin/api/targets/${tPerms}/keys`, { method: 'POST', headers: ah, body: JSON.stringify({ keys: 'sk-bad1\nsk-pro-a\nsk-pro-b' }) });
    r = await jfetch(POOL + `/admin/api/targets/${tPerms}/gateway-keys`, { method: 'POST', headers: ah, body: JSON.stringify({ note: 'perms' }) });
    const gkP = r.body.record.key;
    const ph = { 'content-type': 'application/json', authorization: 'Bearer ' + gkP };
    const mockHits = async () => (await jfetch(MOCK + '/__hits')).body;

    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: ph, body: JSON.stringify({ model: 'mkonly-1', messages: [{ role: 'user', content: 'hi' }] }) });
    const used1 = String((r.body.choices && r.body.choices[0].message.content) || '');
    ok(r.status === 200 && used1.includes('sk-pro'), '不支持该模型的密钥被自动跳过（第 1 次）', `status=${r.status} content=${used1}`);
    let hits = await mockHits();
    ok(hits['sk-bad1'] === 1, '首次请求确实撞过 sk-bad1 一次', JSON.stringify(hits));

    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: ph, body: JSON.stringify({ model: 'mkonly-1', messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 200, '同模型第 2 次请求成功', `status=${r.status}`);
    hits = await mockHits();
    ok(hits['sk-bad1'] === 1, '被屏蔽的密钥不再被该模型请求浪费（sk-bad1 仍为 1 次）', JSON.stringify(hits));

    const permsTg = (await jfetch(POOL + '/admin/api/targets', { headers: ah })).body.targets.find((x) => x.id === tPerms);
    const badKid = permsTg.keys.find((k) => k.key === 'sk-bad1').id;
    const kstates = (await jfetch(POOL + '/admin/api/keystates', { headers: ah })).body.states.filter((x) => x.targetId === tPerms);
    const badSt = kstates.find((x) => x.keyId === badKid);
    ok(badSt && badSt.status === 'ok' && badSt.enabled !== false && /invalid model/.test(badSt.lastError || ''), 'sk-bad1 未被冷却/禁用（模型屏蔽与密钥健康解耦），仅记录原因', JSON.stringify(badSt));

    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: ph, body: JSON.stringify({ model: 'mock-model-a', messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 200, 'sk-bad1 支持的其他模型完全不受影响');
    hits = await mockHits();
    ok(hits['sk-bad1'] >= 2, '其他模型请求仍会用到该密钥（证明未全局冷却）', JSON.stringify(hits));

    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: ph, body: JSON.stringify({ model: 'mkall-1', messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 400 && r.body.error.code === 'model_not_supported', '所有密钥均不支持该模型时返回 400 model_not_supported', `status=${r.status} body=${JSON.stringify(r.body).slice(0, 120)}`);
    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: ph, body: JSON.stringify({ model: 'mock-model-a', messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 200, '全模型不支持报错后渠道整体仍可正常服务', `status=${r.status}`);
    await jfetch(POOL + `/admin/api/targets/${tPerms}`, { method: 'DELETE', headers: ah });

    console.log('— 渠道禁用与 404 —');
    r = await jfetch(POOL + `/admin/api/targets/${t1}`, { method: 'PUT', headers: ah, body: JSON.stringify({ enabled: false }) });
    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model: 'mock-model-a', messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 503 && r.body.error.code === 'no_provider', '全部 OpenAI 型渠道禁用时返回 503');
    await jfetch(POOL + `/admin/api/targets/${t1}`, { method: 'PUT', headers: ah, body: JSON.stringify({ enabled: true }) });
    r = await jfetch(POOL + '/v1/foo/bar', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    ok(r.status === 404, '未知网关路径返回 404');

    console.log('— 渠道专属 Key（隔离路由） —');
    r = await jfetch(POOL + `/admin/api/targets/${t1}/gateway-keys`, { method: 'POST', headers: ah, body: JSON.stringify({ note: 'agent-A' }) });
    ok(r.status === 200 && String(r.body.record.key).startsWith('kp-mockopenai-'), '自动生成专属 Key（kp-渠道名-xxx）', JSON.stringify(r.body).slice(0, 150));
    const gkA = r.body.record.key;
    const gkAId = r.body.record.id;
    r = await jfetch(POOL + `/admin/api/targets/${t1}/gateway-keys`, { method: 'POST', headers: ah, body: JSON.stringify({ key: 'my-custom-agent-key', note: '手动指定' }) });
    ok(r.status === 200 && r.body.record.key === 'my-custom-agent-key', '手动指定专属 Key');
    r = await jfetch(POOL + `/admin/api/targets/${t1}/gateway-keys`, { method: 'POST', headers: ah, body: JSON.stringify({ key: 'my-custom-agent-key' }) });
    ok(r.status === 409, '重复专属 Key 被拒绝（409）');

    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model: 'mock-model-a', messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 401, '存在专属 Key 后，匿名访问被拒绝');
    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + gkA }, body: JSON.stringify({ model: 'mock-model-a', messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 200 && r.headers.get('x-keypool-target') === 'MockOpenAI', '专属 Key 请求路由到绑定渠道', `status=${r.status} target=${r.headers.get('x-keypool-target')}`);

    // 禁用绑定渠道：专属 Key 快速失败，不会落到其他可用渠道
    await jfetch(POOL + `/admin/api/targets/${t1}`, { method: 'PUT', headers: ah, body: JSON.stringify({ enabled: false }) });
    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + gkA }, body: JSON.stringify({ model: 'mock-model-a', messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 403 && r.body.error.code === 'target_disabled', '渠道禁用后专属 Key 返回 403（不落到其他渠道）', `status=${r.status} code=${r.body.error && r.body.error.code}`);
    await jfetch(POOL + `/admin/api/targets/${t1}`, { method: 'PUT', headers: ah, body: JSON.stringify({ enabled: true }) });

    // 专属 Key 的 /v1/models 跨密钥聚合（模型授权按 Key 下发时列表保持稳定完整）
    r = await jfetch(POOL + '/v1/models', { headers: { authorization: 'Bearer ' + gkA } });
    const mids = (r.body.data || []).map((m) => m.id);
    ok(r.status === 200 && mids.includes('mock-only-in-a') && mids.includes('mock-model-b'), '/v1/models 跨密钥聚合：不同 Key 的模型并集完整', JSON.stringify(mids));
    ok(!!r.headers.get('x-keypool-keys'), '聚合响应标记贡献密钥数', String(r.headers.get('x-keypool-keys')));
    r = await jfetch(POOL + '/v1/models', { headers: { authorization: 'Bearer ' + gkA } });
    ok(r.headers.get('x-keypool-cache') === 'hit', '30s 内重复请求命中缓存', String(r.headers.get('x-keypool-cache')));
    ok(r.status === 200 && Array.isArray(r.body.data) && r.body.data.length >= 1, '专属 Key 获取模型列表（仅绑定渠道）');

    // 路径别名：客户端 base 未带 /v1 时（最常见的填错方式）也必须可用
    r = await jfetch(POOL + '/models', { headers: { authorization: 'Bearer ' + gkA } });
    ok(r.status === 200 && Array.isArray(r.body.data) && r.body.data.length >= 1, '别名路径 GET /models 可用（base 未带 /v1）', `status=${r.status}`);
    r = await jfetch(POOL + '/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + gkA }, body: JSON.stringify({ model: 'mock-model-a', messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 200 && r.body.choices, '别名路径 POST /chat/completions 可用', `status=${r.status}`);

    // 禁用专属 Key → 401；重新启用 → 恢复
    await jfetch(POOL + `/admin/api/targets/${t1}/gateway-keys/${gkAId}`, { method: 'PATCH', headers: ah, body: JSON.stringify({ enabled: false }) });
    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + gkA }, body: JSON.stringify({ model: 'mock-model-a', messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 401, '禁用专属 Key 后请求被拒绝');
    await jfetch(POOL + `/admin/api/targets/${t1}/gateway-keys/${gkAId}`, { method: 'PATCH', headers: ah, body: JSON.stringify({ enabled: true }) });

    // 使用统计
    await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + gkA }, body: JSON.stringify({ model: 'mock-model-a', messages: [{ role: 'user', content: 'hi' }] }) });
    const gkList2 = (await jfetch(POOL + '/admin/api/targets', { headers: ah })).body.targets.find((x) => x.id === t1).gatewayKeys;
    const gkRec2 = gkList2.find((x) => x.key === gkA);
    ok(gkRec2.stats && gkRec2.stats.requests >= 1 && gkRec2.stats.success >= 1, '专属 Key 使用统计被记录', JSON.stringify(gkRec2.stats));

    console.log('— OpenAI 型渠道接受 Anthropic 协议（acceptAnthropic） —');
    // 很多国产聚合平台（tierflow/SenseAudio 等）在 OpenAI 兼容 base 上同时暴露 /v1/messages
    r = await jfetch(POOL + '/admin/api/targets', { method: 'POST', headers: ah, body: JSON.stringify({ name: 'MockBridge', type: 'openai', baseUrl: MOCK + '/v1', acceptAnthropic: true }) });
    const tb = r.body.target.id;
    ok(tb && r.body.target.acceptAnthropic === true, '创建渠道时开启 acceptAnthropic');
    await jfetch(POOL + `/admin/api/targets/${tb}/keys`, { method: 'POST', headers: ah, body: JSON.stringify({ keys: 'sk-br1' }) });
    r = await jfetch(POOL + `/admin/api/targets/${tb}/gateway-keys`, { method: 'POST', headers: ah, body: JSON.stringify({ note: 'b' }) });
    const gkB = r.body.record.key;
    const ah2 = { 'content-type': 'application/json', 'x-api-key': gkB, 'anthropic-version': '2023-06-01' };
    r = await jfetch(POOL + '/v1/messages', { method: 'POST', headers: ah2, body: JSON.stringify({ model: 'mock-model-a', max_tokens: 8, messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 200 && String(JSON.stringify(r.body)).includes('Anthropic hello from sk-br1'), '开启后专属 Key 可用 Anthropic 协议调用该渠道', `status=${r.status} ${JSON.stringify(r.body).slice(0, 120)}`);
    r = await jfetch(POOL + '/models', { headers: { 'x-api-key': gkB } });
    ok(r.status === 200 && Array.isArray(r.body.data), 'Anthropic 客户端取模型列表（无前缀别名路径）可用', JSON.stringify(r.body).slice(0, 100));

    await jfetch(POOL + `/admin/api/targets/${tb}`, { method: 'PUT', headers: ah, body: JSON.stringify({ acceptAnthropic: false }) });
    r = await jfetch(POOL + '/v1/messages', { method: 'POST', headers: ah2, body: JSON.stringify({ model: 'mock-model-a', max_tokens: 8, messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 400 && r.body.error.code === 'protocol_mismatch', '关闭后同请求返回 protocol_mismatch', `status=${r.status}`);
    ok(/勾选|开启/.test(r.body.error.message), '错误信息给出可操作指引', r.body.error.message);
    await jfetch(POOL + `/admin/api/targets/${tb}`, { method: 'DELETE', headers: ah });

    console.log('— 渠道模型池 —');
    // 测试 / 加密钥会自动拉取上游模型并持久化到渠道模型池
    r = await jfetch(POOL + `/admin/api/targets/${t1}/models`, { headers: ah });
    ok(Array.isArray(r.body.models) && r.body.models.length >= 2, '模型池自动拉取上游模型', JSON.stringify((r.body.models || []).slice(0, 3)));
    ok(r.body.models.some((m) => m.id === 'mock-tts-a' && m.mode === 'tts'), '模型池保留非对话模型并带 mode 标记');
    r = await jfetch(POOL + '/v1/models', { headers: { authorization: 'Bearer ' + gkA } });
    const chatIds = (r.body.data || []).map((m) => m.id);
    ok(!chatIds.includes('mock-tts-a'), '网关模型列表默认过滤非对话模型（chatOnly）', JSON.stringify(chatIds));
    ok(chatIds.includes('mock-only-in-a') && chatIds.includes('mock-model-b'), '无 mode 的模型默认保留', JSON.stringify(chatIds));
    r = await jfetch(POOL + '/v1/models?all=1', { headers: { authorization: 'Bearer ' + gkA } });
    ok((r.body.data || []).some((m) => m.id === 'mock-tts-a'), '?all=1 返回完整模型池');
    r = await jfetch(POOL + `/admin/api/targets/${t1}/models/refresh`, { method: 'POST', headers: ah });
    ok(r.status === 200 && Array.isArray(r.body.models) && r.body.models.length >= 2, '手动刷新模型池端点', JSON.stringify(r.body).slice(0, 90));
    // 模型池路由：全局密钥请求某个模型时，只发给「池子里有这个模型」的渠道
    r = await jfetch(POOL + '/admin/api/targets', { method: 'POST', headers: ah, body: JSON.stringify({ name: 'MockPoolC', type: 'openai', baseUrl: MOCK + '/v1' }) });
    const tc = r.body.target.id;
    await jfetch(POOL + `/admin/api/targets/${tc}/keys`, { method: 'POST', headers: ah, body: JSON.stringify({ keys: 'sk-good-b' }) });
    await jfetch(POOL + `/admin/api/targets/${tc}/models/refresh`, { method: 'POST', headers: ah });
    await jfetch(POOL + '/admin/api/settings', { method: 'PUT', headers: ah, body: JSON.stringify({ apiKeys: ['tk-global-pool'] }) });
    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer tk-global-pool' }, body: JSON.stringify({ model: 'mock-only-in-a', max_tokens: 8, messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 200 && r.headers.get('x-keypool-target') === 'MockOpenAI', '模型池路由：只发给池里含该模型的渠道', `target=${r.headers.get('x-keypool-target')} status=${r.status}`);
    r = await jfetch(POOL + '/v1/chat/completions', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer tk-global-pool' }, body: JSON.stringify({ model: 'mock-model-a', max_tokens: 8, messages: [{ role: 'user', content: 'hi' }] }) });
    ok(r.status === 200, '两渠道池子里都有的模型仍可正常轮换', `status=${r.status}`);
    await jfetch(POOL + '/admin/api/settings', { method: 'PUT', headers: ah, body: JSON.stringify({ apiKeys: [] }) });
    await jfetch(POOL + `/admin/api/targets/${tc}`, { method: 'DELETE', headers: ah });

    // 上游模型列表全挂时回落模型池
    await jfetch(MOCK + '/__modelsfail', {});
    r = await jfetch(POOL + '/v1/models', { headers: { authorization: 'Bearer ' + gkA } });
    ok(r.status === 200 && r.headers.get('x-keypool-models-source') === 'pool' && (r.body.data || []).some((m) => m.id === 'mock-model-a'), '上游模型列表失败时回落渠道模型池', `status=${r.status}`);
    await jfetch(MOCK + '/__modelsfail?off=1', {});

    console.log('— 修改管理密码 —');
    r = await jfetch(POOL + '/admin/api/password', { method: 'POST', headers: ah, body: JSON.stringify({ oldPassword: 'wrong-old', newPassword: 'newpass123' }) });
    ok(r.status === 400 && r.body.error.code === 'wrong_password', '旧密码错误被拒绝');
    r = await jfetch(POOL + '/admin/api/password', { method: 'POST', headers: ah, body: JSON.stringify({ oldPassword: 'test123456', newPassword: '12345' }) });
    ok(r.status === 400 && r.body.error.code === 'weak_password', '新密码过短被拒绝');
    r = await jfetch(POOL + '/admin/api/password', { method: 'POST', headers: ah, body: JSON.stringify({ oldPassword: 'test123456', newPassword: 'newpass123' }) });
    ok(r.status === 200 && r.body.token, '修改管理密码成功并返回新 token');
    const newTok = r.body.token;
    r = await jfetch(POOL + '/admin/api/overview', { headers: ah });
    ok(r.status === 401, '旧 token 已失效');
    r = await jfetch(POOL + '/admin/api/overview', { headers: { 'x-admin-token': newTok } });
    ok(r.status === 200, '新 token 可用');
    await jfetch(POOL + '/admin/api/password', { method: 'POST', headers: { 'content-type': 'application/json', 'x-admin-token': newTok }, body: JSON.stringify({ oldPassword: 'newpass123', newPassword: 'test123456' }) });
    ok(true, '密码已改回（后续部署校验用 test123456 不受影响）');

    console.log('— 并发上限设置 / 配置导入导出 —');
    r = await jfetch(POOL + '/admin/api/settings', { method: 'POST', headers: ah, body: JSON.stringify({ maxConcurrentPerKey: 2 }) });
    if (r.status === 404) r = await jfetch(POOL + '/admin/api/settings', { method: 'PUT', headers: ah, body: JSON.stringify({ maxConcurrentPerKey: 2 }) });
    ok(r.status === 200, '设置单 Key 最大并发上限');
    const sAfter = (await jfetch(POOL + '/admin/api/settings', { headers: ah })).body.settings;
    ok(sAfter.maxConcurrentPerKey === 2, '单 Key 最大并发设置生效', JSON.stringify(sAfter.maxConcurrentPerKey));

    r = await jfetch(POOL + '/admin/api/export', { headers: ah });
    const exportOk = r.status === 200 && r.body.state && Array.isArray(r.body.state.targets) && r.body.state.targets.length === 2;
    ok(exportOk, '导出配置包含全部渠道与设置', `targets=${r.body.state && r.body.state.targets ? r.body.state.targets.length : 'n/a'}`);
    r = await jfetch(POOL + '/admin/api/import', { method: 'POST', headers: ah, body: JSON.stringify(r.body) });
    ok(r.status === 200 && r.body.targets === 2, '导入配置成功（渠道数保持）', JSON.stringify(r.body).slice(0, 100));
    r = await jfetch(POOL + '/admin/api/targets', { headers: ah });
    const gwTotal = r.body.targets.reduce((s, t) => s + (t.gatewayKeys || []).length, 0);
    ok(r.body.targets.length === 2 && gwTotal >= 2, '导入后渠道与专属 Key 完整保留', `targets=${r.body.targets.length} gwKeys=${gwTotal}`);
    r = await jfetch(POOL + '/admin/api/overview', { headers: ah });
    ok(r.body.concurrent === 0 && typeof r.body.gatewayKeys === 'number', '概览含并发与专属 Key 统计', JSON.stringify({ c: r.body.concurrent, g: r.body.gatewayKeys }));

    console.log(`\n结果：${passCount} 通过，${failCount} 失败`);
    process.exitCode = failCount ? 1 : 0;
  } catch (e) {
    console.error('测试异常:', e);
    process.exitCode = 1;
  } finally {
    pool.kill('SIGTERM');
    mock.close();
    try {
      fs.rmSync(dataDir, { recursive: true, force: true });
    } catch {}
  }
}

main();
