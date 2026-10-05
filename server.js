#!/usr/bin/env node
'use strict';
/*
 * KeyPool — 本地 API Key 轮换池平台
 * - 多平台（Provider）：自定义 base_url，OpenAI / Anthropic / Gemini / Azure 等
 * - 多 API Key：单密钥 / 批量导入（每行一个，可选 "key priority" / "key|note"）
 * - 故障自动轮换：429 / 5xx / 超时 / 网络错误自动切换下一个可用 Key
 * - 冷却熔断：429 按指数退避冷却；401/403 自动禁用；欠费类错误自动冷却
 * - 流式透传：SSE（data: 分块）与 usage 统计兼容
 * - 上游连接池：keep-alive 长连接 + DNS 缓存 + 压缩响应透明解压，热路径首字更快
 * - 内置 Web 管理后台 + 统计 + 日志
 * 零第三方依赖，Node >= 18。
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { Readable } = require('stream');
const net = require('net');
const zlib = require('zlib');
const dns = require('dns');

/* ------------------------------ 启动参数 / 环境变量 ------------------------------ */

function argValue(name) {
  const i = process.argv.indexOf('--' + name);
  if (i >= 0 && process.argv[i + 1]) return process.argv[i + 1];
  return undefined;
}

const PORT = parseInt(argValue('port') || process.env.PORT || '8787', 10);
const HOST = argValue('host') || process.env.HOST || '127.0.0.1';
// 明文 HTTP 监听地址：默认与 HOST 一致；开启 TLS 对外时建议 --http-host 127.0.0.1 只留本机
const HTTP_HOST = argValue('http-host') || process.env.KEYPOOL_HTTP_HOST || HOST;
const DATA_DIR = argValue('data-dir') || process.env.KEYPOOL_DATA_DIR || path.join(__dirname, 'data');
const STATE_FILE = path.join(DATA_DIR, 'state.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

/* ------------------------------ 工具函数 ------------------------------ */

const now = () => Date.now();
const randomHex = (n) => crypto.randomBytes(n).toString('hex');

function sha256(text) {
  return crypto.createHash('sha256').update(String(text)).digest('hex');
}

function hmacSha256(key, text) {
  return crypto.createHmac('sha256', String(key)).update(String(text)).digest('hex');
}

function maskKey(key) {
  const s = String(key || '');
  if (s.length <= 10) return s.slice(0, 3) + '****';
  return s.slice(0, 6) + '****' + s.slice(-4);
}

/* 渠道专属网关密钥：kp-<渠道名拼音/原文安全化>-<随机> */
function genGatewayKey(targetName) {
  const safe = String(targetName || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 16);
  return 'kp-' + (safe ? safe + '-' : '') + randomHex(12);
}

function gatewayKeyTaken(key) {
  const hash = sha256Hex(key);
  for (const t of state.targets) {
    for (const g of t.gatewayKeys || []) {
      if (sha256Hex(g.key) === hash) return true;
    }
  }
  const s = state.settings;
  if (s.apiKeys && s.apiKeys.length) {
    return s.apiKeys.some((k) => sha256Hex(String(k).trim()) === hash);
  }
  return false;
}

function safeJSON(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function clampInt(v, min, max, dft) {
  const n = parseInt(v, 10);
  if (!Number.isFinite(n)) return dft;
  return Math.min(max, Math.max(min, n));
}

function fmtTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  const p = (x) => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function fmtMs(ms) {
  if (ms >= 1000) return (ms / 1000).toFixed(1) + 's';
  return ms + 'ms';
}

/* ------------------------------ 持久化 ------------------------------ */

let state = null;
let saveTimer = null;

function saveState(immediate) {
  if (immediate) {
    if (saveTimer) {
      clearTimeout(saveTimer);
      saveTimer = null;
    }
    try {
      fs.mkdirSync(DATA_DIR, { recursive: true });
      const tmp = STATE_FILE + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(state, null, 2));
      fs.renameSync(tmp, STATE_FILE);
    } catch (e) {
      console.error('[keypool] save state failed:', e.message);
    }
    return;
  }
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    saveState(true);
  }, 300);
}

function defaultTarget() {
  return {
    id: 'p-' + randomHex(6),
    name: '',
    baseUrl: '',
    type: 'openai', // openai | anthropic | gemini | azure
    enabled: true,
    note: '',
    azureApiVersion: '2024-10-21',
    anthropicVersion: '2023-06-01',
    anthropicModel: 'claude-3-5-haiku-20241022',
    testModel: '',
    acceptAnthropic: false, // openai 兼容型渠道是否同时接受 Anthropic 协议（/v1/messages）
    chatOnly: true, // 网关 /v1/models 是否过滤掉上游标记为非对话的模型（TTS/ASR/图像等）
    models: [], // 渠道模型池：上游模型列表快照 { id, name?, mode?, vendor?, desc? }
    modelsUpdatedAt: 0,
    modelsNote: '',
    keys: [], // { key, enabled, priority, note, addedAt } 上游密钥
    gatewayKeys: [], // { id, key, enabled, note, createdAt, stats } 渠道专属网关密钥
    createdAt: now(),
  };
}

function defaultState() {
  return {
    version: 1,
    adminPasswordHash: '', // 空 = 首次需设置
    settings: {
      streamPassthrough: true,
      rateCooldownSeconds: 8,
      serverCooldownSeconds: 5,
      networkCooldownSeconds: 3,
      billingCooldownMinutes: 60,
      requestTimeoutSeconds: 300,
      streamIdleTimeoutSeconds: 120,
      maxAttempts: 6,
      maxBodyMB: 100,
      billingKeywords: 'credit,balance,quota,欠费,余额,arrear,insufficient',
      rotationStrategy: 'round-robin',
      maxConcurrentPerKey: 0,
      notes: '429 按 8s 指数退避；401/403 自动禁用；欠费类自动冷却',
    },
    targets: [],
    logs: [],
  };
}

function loadState() {
  try {
    if (fs.existsSync(STATE_FILE)) {
      const raw = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
      state = Object.assign(defaultState(), raw);
      state.settings = Object.assign(defaultState().settings, raw.settings || {});
      if (!Array.isArray(state.targets)) state.targets = [];
      if (!Array.isArray(state.logs)) state.logs = [];
      for (const t of state.targets) {
        t.keys = Array.isArray(t.keys) ? t.keys : [];
        for (const k of t.keys) {
          k.priority = k.priority || 0;
          k.enabled = k.enabled !== false;
          k.note = k.note || '';
        }
        t.gatewayKeys = Array.isArray(t.gatewayKeys) ? t.gatewayKeys : [];
        for (const g of t.gatewayKeys) {
          g.enabled = g.enabled !== false;
          g.note = g.note || '';
          if (!g.stats) g.stats = { requests: 0, success: 0, fail: 0, lastUsed: 0 };
        }
      }
      return;
    }
  } catch (e) {
    console.error('[keypool] load state failed, start fresh:', e.message);
  }
  state = defaultState();
}

/* ------------------------------ 日志 ------------------------------ */

function addLog(level, msg) {
  state.logs.unshift({ t: now(), level, msg });
  if (state.logs.length > 500) state.logs.length = 500;
  if (level === 'error' || level === 'warn') console.log(`[keypool][${level}] ${msg}`);
}

/* ------------------------------ 请求体读取 ------------------------------ */

function readRequestBody(req, maxMB) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let done = false;
    req.on('data', (c) => {
      if (done) return;
      size += c.length;
      if (size > maxMB * 1024 * 1024) {
        done = true;
        reject(new Error('body_too_large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!done) {
        done = true;
        resolve(Buffer.concat(chunks));
      }
    });
    req.on('error', (e) => {
      if (!done) {
        done = true;
        reject(e);
      }
    });
  });
}

async function readBodySafely(res, maxBytes) {
  // 带大小上限地读取响应体为文本；兼容 fetch 的 web Response 与自研连接池的 Node 流
  const limit = maxBytes || 512 * 1024;
  if (res && typeof res.on === 'function' && typeof res.resume === 'function') {
    return new Promise((resolve) => {
      const chunks = [];
      let size = 0;
      let done = false;
      const part = () => Buffer.concat(chunks).toString('utf8');
      const finish = (txt) => {
        if (!done) {
          done = true;
          resolve(txt);
        }
      };
      res.on('data', (c) => {
        if (done) return;
        size += c.length;
        chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
        if (size > limit) {
          done = true;
          try {
            res.destroy();
          } catch {}
          resolve(part() + '…(truncated)');
        }
      });
      res.on('end', () => finish(part()));
      res.on('error', () => finish(part()));
    });
  }
  if (!res || !res.body) {
    try {
      return String((await res.text()) || '');
    } catch {
      return '';
    }
  }
  const reader = res.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      chunks.push(Buffer.from(value));
      if (size > limit) {
        try {
          await reader.cancel();
        } catch {}
        return Buffer.concat(chunks).toString('utf8') + '…(truncated)';
      }
    }
  } catch {
    // 上游中断：返回已读部分
  }
  return Buffer.concat(chunks).toString('utf8');
}

/* ------------------------------ HTTP 基础响应 ------------------------------ */

function sendJSON(h, status, obj, extraHeaders) {
  const body = JSON.stringify(obj);
  h.writeHead(status, Object.assign({ 'content-type': 'application/json; charset=utf-8' }, extraHeaders || {}));
  h.end(body);
}

function sendError(h, status, code, message, extraHeaders) {
  sendJSON(h, status, { error: { message, type: code, code } }, extraHeaders);
}

function sendText(h, status, text) {
  h.writeHead(status, { 'content-type': 'text/plain; charset=utf-8' });
  h.end(text);
}

/* ------------------------------ 管理后台鉴权 ------------------------------ */

function adminTokenFor() {
  if (!state.adminPasswordHash) return '';
  return hmacSha256(state.adminPasswordHash, 'kp-admin-token-v1');
}

function getAdminToken(req) {
  return (
    req.headers['x-admin-token'] ||
    (() => {
      try {
        const c = req.headers.cookie || '';
        const m = /(?:^|;\s*)admin_token=([^;]+)/.exec(c);
        return m ? decodeURIComponent(m[1]) : '';
      } catch {
        return '';
      }
    })() ||
    (() => {
      try {
        return new URL(req.url, 'http://x').searchParams.get('admin_token') || '';
      } catch {
        return '';
      }
    })() ||
    ''
  );
}

function requireAdmin(h, req) {
  const want = adminTokenFor();
  if (!want) {
    sendError(h, 401, 'setup_required', '请先设置管理密码（POST /admin/login）');
    return false;
  }
  const got = getAdminToken(req);
  const a = Buffer.from(String(got));
  const b = Buffer.from(String(want));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    sendError(h, 401, 'unauthorized', '管理鉴权失败：请先登录');
    return false;
  }
  return true;
}

/* ------------------------------ 网关鉴权（全局 + 渠道专属） ------------------------------ */

function sha256Hex(text) {
  return crypto.createHash('sha256').update(String(text)).digest('hex');
}

const keyCache = new Map(); // hash -> token record（全局密钥缓存）
let keyCacheLoaded = false;

function checkApiAuth(req, settings) {
  const result = { ok: false, targetId: null, record: null };
  // 全局与渠道专属密钥均未配置 → 网关开放（向后兼容）
  const hasGlobal = !!(settings.apiKeys && settings.apiKeys.length);
  const hasAnyChannelKey = state.targets.some((t) => (t.gatewayKeys || []).length > 0);
  if (!hasGlobal && !hasAnyChannelKey) {
    result.ok = true;
    return result;
  }
  let provided =
    (() => {
      const auth = req.headers['authorization'] || '';
      if (/^bearer\s+/i.test(auth)) return auth.replace(/^bearer\s+/i, '').trim();
      return '';
    })() ||
    req.headers['x-api-key'] ||
    req.headers['x-goog-api-key'] ||
    req.headers['x-auth-token'] ||
    (() => {
      try {
        return new URL(req.url, 'http://x').searchParams.get('key') || '';
      } catch {
        return '';
      }
    })();
  if (!provided) return result;
  const hash = sha256Hex(String(provided).trim());
  // 1) 渠道专属网关密钥 → 绑定到对应渠道（直接扫描，实时生效）
  for (const t of state.targets) {
    for (const g of t.gatewayKeys || []) {
      if (g.enabled !== false && sha256Hex(g.key) === hash) {
        result.ok = true;
        result.targetId = t.id;
        result.record = g;
        return result;
      }
    }
  }
  // 2) 全局网关密钥（settings.apiKeys）→ 可访问全部渠道
  if (hasGlobal) {
    if (!keyCacheLoaded) {
      for (const k of settings.apiKeys) {
        if (k && k.trim()) keyCache.set(sha256Hex(k.trim()), { enabled: true });
      }
      keyCacheLoaded = true;
    }
    const rec = keyCache.get(hash);
    if (rec && rec.enabled) {
      result.ok = true;
    }
  }
  return result;
}

/* ------------------------------ 目标 / 密钥 操作 ------------------------------ */

function findTarget(id) {
  return state.targets.find((t) => t.id === id) || null;
}

function publicTarget(t) {
  return {
    id: t.id,
    name: t.name,
    baseUrl: t.baseUrl,
    type: t.type,
    enabled: t.enabled !== false,
    note: t.note || '',
    azureApiVersion: t.azureApiVersion || '2024-10-21',
    anthropicVersion: t.anthropicVersion || '2023-06-01',
    anthropicModel: t.anthropicModel || 'claude-3-5-haiku-20241022',
    testModel: t.testModel || '',
    acceptAnthropic: !!t.acceptAnthropic,
    chatOnly: t.chatOnly !== false,
    models: t.models || [],
    modelsUpdatedAt: t.modelsUpdatedAt || 0,
    modelsNote: t.modelsNote || '',
    createdAt: t.createdAt,
    gatewayKeys: (t.gatewayKeys || []).map((g) => ({
      id: g.id,
      key: g.key,
      enabled: g.enabled !== false,
      note: g.note || '',
      createdAt: g.createdAt,
      stats: g.stats || { requests: 0, success: 0, fail: 0, lastUsed: 0 },
    })),
    keys: (t.keys || []).map((k) => ({
      id: k.id,
      key: k.key,
      enabled: k.enabled !== false,
      priority: k.priority || 0,
      note: k.note || '',
      addedAt: k.addedAt,
    })),
  };
}

function addKeysToTarget(t, lines, priority, note) {
  const added = [];
  const seen = new Set((t.keys || []).map((k) => k.key));
  for (const raw of lines) {
    let line = String(raw).trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;
    let key = line;
    let kNote = note || '';
    let prio = priority || 0;
    if (line.includes('|')) {
      const parts = line.split('|');
      key = parts[0].trim();
      kNote = (parts[1] || '').trim() || kNote;
      const p = parseInt(parts[2], 10);
      if (Number.isFinite(p)) prio = p;
    } else {
      const m = /^(\S+)\s+(.+)$/.exec(line);
      if (m && !/^sk-|^api|^ai|^tx|^gk|^fk/i.test(m[2])) {
        // "key note" 形式
        key = m[1];
        kNote = m[2].trim();
      }
    }
    if (seen.has(key)) continue;
    seen.add(key);
    const rec = {
      id: 'k-' + randomHex(6),
      key,
      enabled: true,
      priority: prio,
      note: kNote,
      addedAt: now(),
    };
    t.keys.push(rec);
    added.push(rec);
  }
  return added;
}

/* ------------------------------ 轮换引擎 ------------------------------ */

function getEntry(targetId, keyId) {
  const key = 'k:' + targetId + ':' + keyId;
  let e = keyStates.get(key);
  if (!e) {
    e = {
      targetId,
      keyId,
      status: 'ok', // ok | cooling | disabled
      enabled: true,
      coolingUntil: 0,
      failCount: 0,
      failStreak: 0,
      lastStatus: 0,
      lastError: '',
      lastUsed: 0,
      inFlight: 0,
      requests: 0,
      success: 0,
      fail: 0,
      promptTokens: 0,
      completionTokens: 0,
    };
    keyStates.set(key, e);
  }
  return e;
}

const keyStates = new Map();

function entryStatus(e) {
  if (!e.enabled || e.status === 'disabled') return 'disabled';
  // 冷却到期自动复位：status='cooling' 但冷却时刻已过 → 回到 ok（否则该 Key 永久滞留冷却态，只能手动重启用）
  if (e.status === 'cooling' && e.coolingUntil <= now()) {
    e.status = 'ok';
    e.coolingUntil = 0;
    e.failStreak = 0;
  }
  if (e.coolingUntil > now()) return 'cooling';
  return 'ok';
}

function pickCandidates(t) {
  const list = [];
  for (const k of t.keys || []) {
    if (k.enabled === false) continue;
    const e = getEntry(t.id, k.id);
    if (entryStatus(e) !== 'ok') continue;
    list.push({ target: t, key: k, entry: e });
  }
  // 单 Key 最大并发上限（0 = 不限制）：达到上限的 Key 让位；全部到顶时尽力而为
  const maxC = clampInt(state.settings.maxConcurrentPerKey, 0, 1000, 0);
  let pool = list;
  if (maxC > 0 && list.length) {
    const below = list.filter((c) => (c.entry.inFlight || 0) < maxC);
    if (below.length) pool = below;
  }
  const byPriority = state.settings.rotationStrategy === 'priority';
  pool.sort((a, b) => {
    if (byPriority) {
      const p = (b.key.priority || 0) - (a.key.priority || 0);
      if (p) return p;
    }
    const ia = a.entry.inFlight || 0;
    const ib = b.entry.inFlight || 0;
    if (ia !== ib) return ia - ib; // 并发少者优先（负载均衡，避免并发请求挤同一个 Key）
    return (a.entry.lastUsed || 0) - (b.entry.lastUsed || 0); // 同负载时最久未用优先（轮询）
  });
  return pool;
}

// 全池冷却时，最早恢复的剩余秒数（用于 Retry-After）
function earliestCooldownSec() {
  let min = Infinity;
  for (const t of state.targets) {
    for (const k of t.keys || []) {
      const e = getEntry(t.id, k.id);
      if (e.enabled !== false && e.coolingUntil > now()) min = Math.min(min, e.coolingUntil - now());
    }
  }
  if (!Number.isFinite(min)) return 5;
  return Math.min(300, Math.max(1, Math.ceil(min / 1000)));
}

function poolAvailableKeys() {
  let ok = 0,
    cooling = 0,
    disabled = 0;
  for (const t of state.targets) {
    for (const k of t.keys || []) {
      const s = entryStatus(getEntry(t.id, k.id));
      if (s === 'ok') ok++;
      else if (s === 'cooling') cooling++;
      else disabled++;
    }
  }
  return { ok, cooling, disabled };
}

function recordSuccess(target, keyRec, entry) {
  entry.status = 'ok';
  entry.coolingUntil = 0;
  entry.failStreak = 0;
  entry.failCount = 0;
  entry.lastStatus = 200;
  entry.lastError = '';
  entry.lastUsed = now();
  entry.requests++;
  entry.success++;
}

function recordFailure(target, keyRec, entry, kind, status, note, headers, model) {
  entry.lastUsed = now();
  entry.requests++;
  entry.fail++;
  entry.failCount++;
  entry.lastStatus = status || 0;
  entry.lastError = note || '';
  const s = state.settings;
  if (kind === 'auth') {
    entry.enabled = false;
    entry.status = 'disabled';
    entry.coolingUntil = 0;
    addLog('warn', `密钥 ${maskKey(keyRec.key)} @ ${target.name} 鉴权失败（${status}），已自动禁用：${note}`);
  } else if (kind === 'billing') {
    entry.status = 'cooling';
    entry.coolingUntil = now() + clampInt(s.billingCooldownMinutes, 1, 10080, 60) * 60000;
    addLog('warn', `密钥 ${maskKey(keyRec.key)} @ ${target.name} 疑似欠费/额度不足，冷却 ${s.billingCooldownMinutes} 分钟：${note}`);
  } else if (kind === 'rate') {
    entry.failStreak++;
    let wait = 0;
    let fromHeader = false;
    const ra = headers && headers.get ? headers.get('retry-after') || '' : '';
    if (ra) {
      // 支持秒数或 HTTP 日期两种 Retry-After 格式
      const secs = /^\d+(\.\d+)?$/.test(ra.trim())
        ? parseFloat(ra)
        : Number.isFinite(Date.parse(ra))
          ? Math.round((Date.parse(ra) - Date.now()) / 1000)
          : NaN;
      if (Number.isFinite(secs) && secs > 0) {
        wait = Math.min(secs * 1000, 30 * 60000);
        fromHeader = true;
      }
    }
    if (!wait) {
      const base = clampInt(s.rateCooldownSeconds, 1, 3600, 8) * 1000;
      wait = Math.min(base * Math.pow(2, Math.min(entry.failStreak - 1, 6)), 30 * 60000);
      wait = Math.round(wait * (0.9 + Math.random() * 0.2)); // ±10% 抖动，避免密钥同时恢复同时打挂
    }
    entry.status = 'cooling';
    entry.coolingUntil = now() + wait;
    addLog('warn', `密钥 ${maskKey(keyRec.key)} @ ${target.name} 触发限流（429），冷却 ${fmtMs(wait)} 后重试${fromHeader ? '（遵循上游 Retry-After）' : ''}`);
  } else if (kind === 'model') {
    // 该密钥不支持所请求的**这个模型**（常见于聚合平台按 Key 分配模型权限）。
    // 只按「密钥+模型」粒度短时屏蔽，绝不冷却/禁用密钥本身——它对其他模型完全健康。
    if (model) blockModelFor(target.id, keyRec.id, model);
    addLog('warn', `密钥 ${maskKey(keyRec.key)} @ ${target.name} 不支持模型「${model || '?'}」，60s 内该模型跳过此密钥：${note}`);
  } else if (kind === 'server') {
    const base = clampInt(s.serverCooldownSeconds, 1, 3600, 5) * 1000;
    entry.status = 'cooling';
    entry.coolingUntil = now() + Math.round(base * (0.85 + Math.random() * 0.3));
    addLog('warn', `密钥 ${maskKey(keyRec.key)} @ ${target.name} 上游 ${status}，短暂冷却`);
  } else if (kind === 'timeout' || kind === 'network') {
    const base = clampInt(s.networkCooldownSeconds, 1, 3600, 3) * 1000;
    entry.status = 'cooling';
    entry.coolingUntil = now() + Math.round(base * (0.85 + Math.random() * 0.3));
    addLog('warn', `密钥 ${maskKey(keyRec.key)} @ ${target.name} ${kind === 'timeout' ? '请求超时' : '网络错误'}，短暂冷却：${note}`);
  }
}

function recordUsage(target, keyRec, entry, usage, started) {
  if (!usage) return;
  const pt = usage.prompt_tokens || usage.input_tokens || 0;
  const ct = usage.completion_tokens || usage.output_tokens || 0;
  if (pt) entry.promptTokens += pt;
  if (ct) entry.completionTokens += ct;
}

/* 模型权限关键词：上游 4xx 命中时视为“该密钥不支持所请求模型”，轮换到下一个密钥
 * （多租户聚合平台常见：同一渠道各密钥可用的模型集合不同） */
const MODEL_KW = ['invalid model', 'model not found', 'model_not_found', 'unsupported model', 'no such model', '模型不存在', '不支持的模型', '无可用模型', '模型未找到', '未找到模型', '没有找到模型', '找不到模型', '无此模型'];

/* 「密钥+模型」短时屏蔽表（纯内存，不污染密钥健康状态）：
 * 上游确认某密钥不支持某模型后，60s 内该模型的请求跳过这个密钥，其他模型不受影响；
 * 到期自动放行重新探测（平台侧权限可能变化）。 */
const MODEL_BLOCK_MS = 60000;
const modelBlock = new Map(); // "targetId|keyId|model" -> 解除时间
function blockModelFor(targetId, keyId, model) {
  if (modelBlock.size > 5000) {
    for (const [mk, until] of modelBlock) if (until <= now()) modelBlock.delete(mk);
  }
  modelBlock.set(targetId + '|' + keyId + '|' + model, now() + MODEL_BLOCK_MS);
}
function isModelBlocked(targetId, keyId, model) {
  if (!model) return false;
  const mk = targetId + '|' + keyId + '|' + model;
  const until = modelBlock.get(mk);
  if (!until) return false;
  if (until <= now()) {
    modelBlock.delete(mk);
    return false;
  }
  return true;
}

function classifyFailure(status, bodyText, settings) {
  if (status === 401 || status === 403) return 'auth';
  if (status === 429) return 'rate';
  if (status === 402 || status === 404) {
    const low = String(bodyText || '').toLowerCase();
    const kws = String(settings.billingKeywords || '')
      .split(',')
      .map((x) => x.trim().toLowerCase())
      .filter(Boolean);
    if (kws.some((w) => low.includes(w))) return 'billing';
    if (MODEL_KW.some((w) => low.includes(w))) return 'model';
    return status === 402 ? 'billing' : null; // 404 模型不存在等不轮换
  }
  if (status >= 500) return 'server';
  if (status >= 400) {
    const low = String(bodyText || '').toLowerCase();
    const kws = String(settings.billingKeywords || '')
      .split(',')
      .map((x) => x.trim().toLowerCase())
      .filter(Boolean);
    if (kws.some((w) => low.includes(w))) return 'billing';
    if (MODEL_KW.some((w) => low.includes(w))) return 'model';
  }
  return null;
}

function extractErrNote(text) {
  const j = safeJSON(text);
  if (j) {
    if (j.error) return String(j.error.message || j.error.type || JSON.stringify(j.error)).slice(0, 300);
    if (j.message) return String(j.message).slice(0, 300);
    if (j.detail) return String(j.detail).slice(0, 300);
  }
  return String(text || '').slice(0, 200);
}

/* ------------------------------ 上游 URL / 头构造 ------------------------------ */

function joinBase(base, suffix) {
  return base.replace(/\/+$/, '') + suffix;
}

function azureDeploymentOf(pathname) {
  // /openai/deployments/<dep>/chat/completions
  const m = /\/openai\/deployments\/([^/]+)/.exec(pathname);
  return m ? m[1] : '';
}

function upstreamURL(t, provider, pathname) {
  const base = String(t.baseUrl || '').trim().replace(/\/+$/, '');
  if (t.type === 'azure') {
    const dep = azureDeploymentOf(pathname);
    const after = pathname.replace(/^\/openai\/deployments\/[^/]+/, '');
    return joinBase(base, '/openai/deployments/' + encodeURIComponent(dep) + after) + '?api-version=' + encodeURIComponent(t.azureApiVersion || '2024-10-21');
  }
  if (t.type === 'gemini') {
    // Gemini 原生路径：/v1beta/... 直接拼接
    return joinBase(base, pathname);
  }
  if (t.type === 'anthropic') {
    // Anthropic 官方习惯：base 不带 /v1；用户填了 /v1 结尾时自动归一，避免 /v1/v1/...
    const nb = withVersion(base, 'v1');
    const p = pathname.startsWith('/v1/') ? pathname.slice(3) : pathname;
    return joinBase(nb, p);
  }
  // OpenAI 兼容平台：base 未带版本号时自动补 /v1
  const nb = /\/v\d+[a-z]*$/i.test(base) ? base : base + '/v1';
  const p = pathname.startsWith('/v1/') ? pathname.slice(3) : pathname;
  if (provider === 'anthropic') {
    // Anthropic 协议打到 OpenAI 兼容平台（如 deepseek 的 anthropic 端点）
    return joinBase(nb, p.replace(/^\/v1/, ''));
  }
  return joinBase(nb, p);
}

function upstreamHeaders(t, keyRec, req, provider, bodyBuf, pathname) {
  const headers = {};
  // 透传安全白名单头
  const pass = ['content-type', 'accept', 'user-agent', 'accept-encoding', 'anthropic-beta', 'openai-organization', 'openai-project'];
  for (const k of pass) {
    if (req.headers[k]) headers[k] = req.headers[k];
  }
  if (!headers['accept']) headers['accept'] = 'application/json';
  if (bodyBuf && bodyBuf.length) headers['content-length'] = String(bodyBuf.length);

  if (t.type === 'azure') {
    headers['api-key'] = keyRec.key;
  } else if (t.type === 'anthropic') {
    headers['x-api-key'] = keyRec.key;
    headers['anthropic-version'] = req.headers['anthropic-version'] || t.anthropicVersion || '2023-06-01';
  } else if (t.type === 'gemini') {
    headers['x-goog-api-key'] = keyRec.key;
  } else {
    headers['authorization'] = 'Bearer ' + keyRec.key;
    // OpenAI 兼容型渠道以 Anthropic 协议接入时，同时带上 x-api-key + 版本头：
    // 兼容只认 Anthropic 约定的上游（如 deepseek 的 /anthropic 端点）
    if (provider === 'anthropic') {
      headers['x-api-key'] = keyRec.key;
      headers['anthropic-version'] = req.headers['anthropic-version'] || t.anthropicVersion || '2023-06-01';
    }
  }
  if (provider === 'anthropic' && t.type === 'anthropic') {
    headers['anthropic-version'] = req.headers['anthropic-version'] || t.anthropicVersion || '2023-06-01';
  }
  return headers;
}

/* ------------------------------ 转发核心 ------------------------------ */

/* ------------------------------ 上游连接池 ------------------------------
 * fetch（undici 全局连接池）默认只保活 4s：聊天场景间隔一超，每次请求都要重付
 * 上游 TCP+TLS 握手（实测 25~400ms）。这里用自带 keep-alive 的 Agent 常驻连接：
 * - 连接复用：热路径省掉握手，首字延迟显著下降
 * - DNS 缓存 120s：新建连接不再每次查域名
 * - 复用 socket 偶发被上游断开（ECONNRESET/EPIPE）时换新连接透明重试一次
 * - 连接建立独立 10s 超时（KEYPOOL_CONNECT_TIMEOUT 可调），死上游快速轮换
 * - 响应带 gzip/deflate/br 时透明解压，转发给客户端的始终是明文字节
 */

const CONNECT_TIMEOUT_MS = clampInt(process.env.KEYPOOL_CONNECT_TIMEOUT, 1000, 120000, 10000);

const dnsCache = new Map(); // "host|family|all" -> { addr, family, until }
function cachedLookup(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  options = options || {};
  const fam = options.family || 0;
  const all = !!options.all;
  // autoSelectFamily（Node ≥20 默认开）用 all:true 调 lookup，回调要求数组形状；两种形状都要支持
  const cacheKey = hostname + '|' + fam + '|' + (all ? 1 : 0);
  const hit = dnsCache.get(cacheKey);
  if (hit && hit.until > now()) {
    process.nextTick(callback, null, hit.addr, hit.family);
    return;
  }
  const req = { family: fam || 0 };
  if (all) req.all = true;
  if (options.hints) req.hints = options.hints;
  dns.lookup(hostname, req, (err, addr, family) => {
    if (!err && addr) {
      if (dnsCache.size > 500) for (const [k, v] of dnsCache) if (v.until <= now()) dnsCache.delete(k);
      dnsCache.set(cacheKey, { addr, family, until: now() + 120000 });
    }
    callback(err, addr, family);
  });
}

const upstreamAgentOpts = {
  keepAlive: true,
  keepAliveMsecs: 30000,
  maxSockets: 256,
  maxFreeSockets: 32,
  scheduling: 'lifo',
  lookup: cachedLookup,
};
const upstreamAgentHttp = new http.Agent(upstreamAgentOpts);
const upstreamAgentHttps = new https.Agent(upstreamAgentOpts);

/* 空闲 socket 回收：上游（尤其是不规范的 LB/CDN）可能对闲置连接静默丢弃且不发 RST，
 * 复用这种半开连接会请求黑等到超时。给归还连接池的 socket 设空闲上限，
 * 超时即销毁；活跃对话（间隔小于该值）仍能命中连接复用。
 * 默认 45s（部分平台对新建连接有明显的排队惩罚，热连接 TTFT 快数倍），
 * KEYPOOL_FREE_SOCKET_IDLE_MS 可调（0 = 不回收）。 */
const FREE_SOCKET_IDLE_MS = clampInt(process.env.KEYPOOL_FREE_SOCKET_IDLE_MS, 0, 600000, 45000);
function armFreeSocketIdle(sock) {
  if (!FREE_SOCKET_IDLE_MS) return;
  if (sock.__kpIdleTimer) clearTimeout(sock.__kpIdleTimer);
  sock.__kpIdleTimer = setTimeout(() => {
    try {
      sock.destroy();
    } catch {}
  }, FREE_SOCKET_IDLE_MS);
  if (sock.__kpIdleTimer.unref) sock.__kpIdleTimer.unref();
}
upstreamAgentHttp.on('free', armFreeSocketIdle);
upstreamAgentHttps.on('free', armFreeSocketIdle);

/* 上游 URL 校验：仅允许 http/https 且必须带主机名（上游地址来自渠道配置） */
function safeUpstreamURL(urlStr) {
  let u;
  try {
    u = new URL(urlStr);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  if (!u.hostname) return null;
  return u;
}

/* 管理侧出站请求（密钥探测 / 模型池拉取）统一走这里：与转发主路径一致先校验 URL */
async function guardedFetch(url, opts) {
  const u = safeUpstreamURL(url);
  if (!u) throw new Error('invalid upstream url');
  return fetch(u.toString(), opts);
}

function upstreamRequest(urlStr, opts) {  return new Promise((resolve) => {
    const u = safeUpstreamURL(urlStr);
    if (!u) {
      resolve({ ok: false, kind: 'network', note: 'invalid upstream url' });
      return;
    }
    const isHttps = u.protocol === 'https:';
    const reqOpts = {
      hostname: u.hostname,
      port: u.port || (isHttps ? 443 : 80),
      path: u.pathname + u.search,
      method: opts.method || 'GET',
      headers: opts.headers || {},
      agent: isHttps ? upstreamAgentHttps : upstreamAgentHttp,
    };
    let settled = false;
    let resSeen = false;
    let retryLeft = 1; // 复用 socket 被上游提前断开时，换新连接重试一次
    let curConnTimer = null;
    const clearConnTimer = () => {
      if (curConnTimer) {
        clearTimeout(curConnTimer);
        curConnTimer = null;
      }
    };
    const ctrl = { aborted: false, abort() {} };
    const settleErr = (kind, note) => {
      if (settled) return;
      settled = true;
      resolve({ ok: false, kind, note: String(note || '').slice(0, 300) });
    };
    const settleRes = (payload) => {
      if (settled) return;
      settled = true;
      resolve(payload);
    };

    const attempt = () => {
      let reqOut;
      try {
        reqOut = (isHttps ? https : http).request(reqOpts, onRes);
      } catch (e) {
        settleErr('network', e.message);
        return;
      }
      ctrl.abort = (msg) => {
        ctrl.aborted = true;
        try {
          reqOut.destroy(new Error(msg || 'aborted'));
        } catch {}
      };
      reqOut.on('socket', (sock) => {
        try {
          sock.setNoDelay(true);
        } catch {}
        if (sock.__kpIdleTimer) {
          clearTimeout(sock.__kpIdleTimer);
          sock.__kpIdleTimer = null;
        }
        if (sock.connecting) {
          // 新建连接：握手完成后解除连接超时；复用的保活 socket 不会再触发 connect，
          // 也不要在上面挂 once 监听（否则随复用次数累积触发 MaxListeners）
          sock.once(isHttps ? 'secureConnect' : 'connect', () => clearConnTimer());
        } else {
          clearConnTimer();
        }
      });
      curConnTimer = setTimeout(() => {
        reqOut.destroy(new Error('connect timeout'));
      }, CONNECT_TIMEOUT_MS);
      reqOut.setTimeout(opts.timeoutMs || 300000, () => {
        reqOut.destroy(new Error('upstream timeout'));
      });
      reqOut.on('error', (e) => {
        clearConnTimer();
        const code = e && e.code;
        const msg = String((e && e.message) || e);
        if (resSeen || settled) return;
        if (retryLeft > 0 && reqOut.reusedSocket && !ctrl.aborted && (code === 'ECONNRESET' || code === 'EPIPE')) {
          retryLeft = 0;
          attempt();
          return;
        }
        settleErr(/timeout/i.test(msg) ? 'timeout' : 'network', msg);
      });
      const body = opts.bodyBuf;
      if (body && body.length && reqOpts.method !== 'GET' && reqOpts.method !== 'HEAD') reqOut.end(body);
      else reqOut.end();
    };

    const onRes = (res) => {
      resSeen = true;
      clearConnTimer();
      // 透明解压：网关转发给客户端的始终是明文字节（旧 fetch 行为一致）
      const enc = String((res.headers && res.headers['content-encoding']) || '')
        .trim()
        .toLowerCase();
      let stream = res;
      if (enc === 'gzip' || enc === 'x-gzip' || enc === 'deflate' || enc === 'br') {
        const dz = enc === 'br' ? zlib.createBrotliDecompress() : enc === 'deflate' ? zlib.createInflate() : zlib.createGunzip();
        stream = res.pipe(dz);
        stream.on('error', () => {
          try {
            res.destroy();
          } catch {}
        });
      }
      res.on('error', () => {});
      stream.body = stream; // 与 fetch Response.body 对齐：真值 + 可异步迭代
      const shimMap = {};
      for (const [k, v] of Object.entries(res.headers || {})) {
        shimMap[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : String(v);
      }
      if (stream !== res) {
        delete shimMap['content-encoding'];
        delete shimMap['content-length'];
      }
      const headers = {
        get(n) {
          const v = shimMap[String(n).toLowerCase()];
          return v === undefined ? null : v;
        },
      };
      settleRes({ ok: true, status: res.statusCode, res: stream, headers, ctrl, url: urlStr });
    };

    attempt();
  });
}

async function tryUpstream(t, keyRec, provider, req, bodyBuf, pathname, mode) {
  const url = upstreamURL(t, provider, pathname);
  const headers = upstreamHeaders(t, keyRec, req, provider, bodyBuf, pathname);
  // 流式请求向上游要 identity（SSE 不压缩，首字节零解压开销）；非流式允许压缩减小传输体积
  headers['accept-encoding'] = mode === 'raw' ? 'identity' : 'gzip, deflate, br';
  const timeoutMs = clampInt(state.settings.requestTimeoutSeconds, 1, 3600, 300) * 1000;
  let target = url;
  for (let hop = 0; hop < 2; hop++) {
    const r = await upstreamRequest(target, { method: req.method, headers, bodyBuf, timeoutMs });
    if (!(r.ok && [301, 302, 307, 308].includes(r.status) && hop === 0)) return r;
    const loc = r.headers.get('location');
    if (!loc) return r;
    let next;
    try {
      next = new URL(loc, target);
    } catch {
      return r;
    }
    if (next.origin !== new URL(target).origin) return r; // 不跨域跟随，避免把鉴权头带去第三方
    try {
      r.res.destroy();
    } catch {}
    target = next.toString();
  }
}

/* ---------------- 渠道模型池 ----------------
 * 每个渠道持久化一份上游模型列表快照：新增密钥 / 连通性测试 / 改 Base URL 时自动拉取，
 * 后台也可手动刷新。网关 GET /v1/models 在上游全部失败时回落到模型池，
 * 保证客户端（DSH、Claude Code 等）"取模型"这一步不会被上游抖动卡死。 */
const CHAT_MODEL_MODES = new Set(['llm', 'chat']);
function modelIsChat(m) {
  const mode = String((m && m.mode) || '').toLowerCase();
  return !mode || CHAT_MODEL_MODES.has(mode);
}
/* 模型池路由用的「渠道模型 ID 集合」缓存：models 数组整体替换式更新，WeakMap 按数组身份缓存，
 * 免去每请求对全量模型列表做 O(n) 归一化字符串比较 */
const MODEL_SET_CACHE = new WeakMap();
function normModelId(x) {
  return String(x || '')
    .trim()
    .toLowerCase()
    .replace(/^models\//, '');
}
function targetHasModel(t, want) {
  const models = t.models || [];
  let set = MODEL_SET_CACHE.get(models);
  if (!set) {
    set = new Set();
    for (const m of models) set.add(normModelId(m && m.id));
    MODEL_SET_CACHE.set(models, set);
  }
  return set.has(want);
}
function slimModelEntry(m) {
  const id = String((m && (m.id || m.name)) || '').slice(0, 200);
  if (!id) return null;
  const e = { id };
  const name = m.display_name || m.name;
  if (name && name !== id) e.name = String(name).slice(0, 200);
  if (m.mode) e.mode = String(m.mode).slice(0, 32);
  if (m.owned_by || m.vendor) e.vendor = String(m.owned_by || m.vendor).slice(0, 64);
  const d = m.desc || m.description;
  if (d) e.desc = String(d).replace(/\s+/g, ' ').slice(0, 180);
  return e;
}
function modelsEndpoint(t) {
  const base = String(t.baseUrl || '').replace(/\/+$/, '');
  if (!base) return null;
  if (t.type === 'azure') return null; // Azure 按部署名调用，没有可按 Key 枚举的模型端点
  if (t.type === 'gemini') return { url: joinBase(withVersion(base, 'v1beta'), '/models') + '?pageSize=1000', mode: 'goog' };
  if (t.type === 'anthropic') return { url: joinBase(withVersion(base, 'v1'), '/models'), mode: 'xapi' };
  return { url: joinBase(withVersion(base, 'v1'), '/models'), mode: 'bearer' };
}
const modelsRefreshInflight = new Set();

async function refreshTargetModels(t, timeoutMs = 20000) {
  const ep = modelsEndpoint(t);
  const keys = (t.keys || []).filter((k) => k.enabled !== false).slice(0, 12);
  if (!ep) {
    t.modelsNote = t.type === 'azure' ? 'Azure 渠道按部署名调用，无模型列表端点' : '该渠道类型不支持模型列表拉取';
    t.modelsUpdatedAt = now();
    saveState();
    return { models: t.models || [], updatedAt: t.modelsUpdatedAt, note: t.modelsNote };
  }
  if (modelsRefreshInflight.has(t.id)) return { models: t.models || [], busy: true };
  modelsRefreshInflight.add(t.id);
  const pool = new Map();
  let ok = 0;
  let fail = 0;
  let firstErr = '';
  try {
    const queue = keys.slice();
    const worker = async () => {
      for (let k = queue.shift(); k; k = queue.shift()) {
        const headers = { accept: 'application/json' };
        if (ep.mode === 'bearer') headers.authorization = 'Bearer ' + k.key;
        else if (ep.mode === 'xapi') {
          headers['x-api-key'] = k.key;
          headers['anthropic-version'] = t.anthropicVersion || '2023-06-01';
        } else headers['x-goog-api-key'] = k.key;
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(new Error('timeout')), timeoutMs);
        try {
          const res = await guardedFetch(ep.url, { method: 'GET', headers, signal: ctrl.signal });
          const text = await readBodySafely(res, 2 * 1024 * 1024);
          if (res.status >= 200 && res.status < 300) {
            const j = safeJSON(text);
            const arr = j && Array.isArray(j.data) ? j.data : j && Array.isArray(j.models) ? j.models : null;
            if (arr) {
              ok++;
              for (const m of arr) {
                const e = slimModelEntry(m);
                if (e) pool.set(e.id, Object.assign({}, pool.get(e.id), e));
              }
              continue;
            }
            fail++;
            if (!firstErr) firstErr = extractErrNote(text).slice(0, 160);
          } else {
            fail++;
            if (!firstErr) firstErr = `HTTP ${res.status} ${extractErrNote(text).slice(0, 140)}`;
          }
        } catch (e) {
          fail++;
          if (!firstErr) firstErr = String((e && e.message) || e).slice(0, 140);
        } finally {
          clearTimeout(timer);
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(4, queue.length) }, worker));
  } finally {
    modelsRefreshInflight.delete(t.id);
  }
  if (ok) {
    const list = [...pool.values()].sort((a, b) => (modelIsChat(a) === modelIsChat(b) ? a.id.localeCompare(b.id) : modelIsChat(a) ? -1 : 1)).slice(0, 800);
    t.models = list;
    t.modelsNote = fail ? `${ok}/${ok + fail} 个密钥返回，${fail} 个失败` : '';
  } else {
    t.modelsNote = firstErr ? `拉取失败：${firstErr}` : (keys.length ? '未获得模型列表' : '渠道还没有可用密钥');
  }
  t.modelsUpdatedAt = now();
  saveState();
  // 模型池变化后让 /v1/models 的聚合缓存失效，避免旧列表掩盖新数据
  for (const ck of [...modelsMergeCache.keys()]) if (ck.includes(t.id + ':')) modelsMergeCache.delete(ck);
  addLog(ok ? 'info' : 'warn', `模型池刷新：${t.name} 共 ${ok ? t.models.length : (t.models || []).length} 个模型（${ok}/${ok + fail} 个密钥成功）${t.modelsNote ? ' · ' + t.modelsNote : ''}`);
  return { models: t.models || [], updatedAt: t.modelsUpdatedAt, note: t.modelsNote };
}

/* 节流式后台刷新：模型池为空或超过 minAgeMs 未更新才真正拉取 */
function maybeRefreshPool(t, force, minAgeMs = 60000) {
  if (!t || !(t.keys || []).length) return;
  if (!force && t.models && t.models.length && now() - (t.modelsUpdatedAt || 0) < minAgeMs) return;
  if (modelsRefreshInflight.has(t.id)) return;
  setTimeout(() => {
    refreshTargetModels(t).catch(() => {});
  }, 0);
}

/* /v1/models 跨密钥聚合：并发拉取各候选密钥的模型列表，按 id/name 去重合并。
 * 聚合平台的模型授权常按 Key 下发，单 Key 拉取会让客户端每次看到不同列表。
 * 2min 结果缓存（避免频繁刷新打爆上游）；全部失败时透传第一个上游错误。
 * 除 401/403（真实的密钥失效信号）外，模型列表拉取失败不影响密钥健康状态。 */
const MODELS_MERGE_TTL = 120000;
const modelsMergeCache = new Map(); // cacheKey -> { until, body, targets, keys }

async function deliverModelsMerged(h, candidates, provider, pathname, grec, url) {
  const all = !!(url && url.searchParams.get('all') === '1');
  const cacheKey = provider + '|' + pathname + '|' + candidates.map((c) => c.target.id + ':' + c.key.id).sort().join(',') + '|' + (all ? 'all' : 'chat');
  const hit = modelsMergeCache.get(cacheKey);
  if (hit && hit.until > now()) {
    if (grec) {
      grec.stats.success++;
      saveState();
    }
    return sendJSON(h, 200, hit.body, { 'x-keypool-target': hit.targets, 'x-keypool-keys': String(hit.keys), 'x-keypool-cache': 'hit' });
  }
  const limit = Math.min(candidates.length, 24);
  const seen = new Set();
  const merged = [];
  const names = [];
  let shape = '';
  let okKeys = 0;
  let firstErr = null;
  const jobs = [];
  for (let i = 0; i < limit; i++) {
    const c = candidates[i];
    c.entry.inFlight = (c.entry.inFlight || 0) + 1;
    jobs.push(
      (async () => {
        try {
          const r = await tryUpstream(c.target, c.key, provider, { method: 'GET', headers: {} }, null, pathname);
          if (!r.ok) {
            if (!firstErr) firstErr = { status: 0, note: r.note, target: c.target.name };
            return;
          }
          const text = await readBodySafely(r.res, 2 * 1024 * 1024);
          if (r.status >= 200 && r.status < 300) {
            const j = safeJSON(text);
            const isData = !!(j && Array.isArray(j.data));
            const arr = isData ? j.data : j && Array.isArray(j.models) ? j.models : null;
            if (!arr) {
              if (!firstErr) firstErr = { status: r.status, body: text, target: c.target.name };
              return;
            }
            recordSuccess(c.target, c.key, c.entry);
            okKeys++;
            if (!names.includes(c.target.name)) names.push(c.target.name);
            if (!shape) shape = isData ? 'data' : 'models';
            const want = shape === 'data' ? (isData ? j.data : []) : isData ? [] : j.models;
            for (const m of want || []) {
              const id = String((m && (m.id || m.name)) || '');
              if (!id || seen.has(id)) continue;
              // 渠道开启「只保留对话模型」时，过滤上游显式标记为非对话的模型（如 TTS/ASR/图像）；
              // 模型池与 ?all=1 仍保留完整列表
              if (!all && c.target.chatOnly !== false && !modelIsChat(m)) continue;
              seen.add(id);
              merged.push(m);
            }
            return;
          }
          if (r.status === 401 || r.status === 403) {
            recordFailure(c.target, c.key, c.entry, 'auth', r.status, extractErrNote(text), r.headers);
          }
          if (!firstErr) firstErr = { status: r.status, body: text, target: c.target.name };
        } catch (e) {
          if (!firstErr) firstErr = { status: 0, note: String((e && e.message) || e), target: c.target.name };
        } finally {
          c.entry.inFlight = Math.max(0, (c.entry.inFlight || 1) - 1);
        }
      })()
    );
  }
  await Promise.all(jobs);

  if (!okKeys) {
    // 回落：上游模型列表全部拉取失败时，使用持久化的渠道模型池，客户端仍能拿到可用模型
    const uniqTargets = [...new Set(candidates.map((c) => c.target))];
    const poolEntries = [];
    const poolSeen = new Set();
    for (const t of uniqTargets) {
      for (const m of t.models || []) {
        if (poolSeen.has(m.id) || (!all && t.chatOnly !== false && !modelIsChat(m))) continue;
        poolSeen.add(m.id);
        poolEntries.push({ id: m.id, object: 'model', mode: m.mode, owned_by: m.vendor, display_name: m.name, desc: m.desc });
      }
    }
    if (poolEntries.length) {
      addLog('warn', `上游模型列表拉取失败，使用渠道模型池兜底（${poolEntries.length} 个模型）：${uniqTargets.map((t) => t.name).join(',')} ${firstErr && firstErr.note ? '· ' + firstErr.note : ''}`);
      for (const t of uniqTargets) maybeRefreshPool(t, true);
      const body = { object: 'list', data: poolEntries };
      if (grec) {
        grec.stats.success++;
        saveState();
      }
      return sendJSON(h, 200, body, {
        'x-keypool-target': uniqTargets.map((t) => t.name).join(','),
        'x-keypool-models-source': 'pool',
      });
    }
    if (grec) {
      grec.stats.fail++;
      saveState();
    }
    if (firstErr && firstErr.status >= 400 && firstErr.body) {
      h.writeHead(firstErr.status, { 'content-type': 'application/json', 'x-keypool-target': firstErr.target || '' });
      return h.end(firstErr.body);
    }
    return sendError(h, 502, 'all_keys_failed', `获取模型列表失败：${(firstErr && (firstErr.note || '上游无有效响应')) || '上游无有效响应'}`, {
      'x-keypool-error': 'exhausted',
    });
  }
  const body = shape === 'models' ? { models: merged } : { object: 'list', data: merged };
  if (grec) {
    grec.stats.success++;
    saveState();
  }
  if (modelsMergeCache.size > 200) {
    for (const [k, v] of modelsMergeCache) if (v.until <= now()) modelsMergeCache.delete(k);
  }
  modelsMergeCache.set(cacheKey, { until: now() + MODELS_MERGE_TTL, body, targets: names.join(','), keys: okKeys });
  addLog('info', `模型列表聚合：${names.join(',')}（${okKeys}/${limit} 个密钥贡献，共 ${merged.length} 个模型）`);
  return sendJSON(h, 200, body, { 'x-keypool-target': names.join(','), 'x-keypool-keys': String(okKeys) });
}

async function relayGateway(h, req, url, provider, pathname) {
  const s = state.settings;
  const auth = checkApiAuth(req, s);
  if (!auth.ok) {
    return sendError(h, 401, 'invalid_api_key', 'Invalid API key provided by client', { 'x-keypool-error': 'auth' });
  }
  const enabled = state.targets.filter((t) => t.enabled !== false && (t.keys || []).length > 0);
  // 协议类型匹配：Anthropic 协议走 Anthropic 型渠道，或显式开启了「接受 Anthropic 协议」的 OpenAI 兼容渠道
  // （很多国产聚合平台同时暴露 /v1/messages）；OpenAI/Gemini 协议不走 Anthropic 型渠道
  const acceptsProto = (t) => (provider === 'anthropic' ? t.type === 'anthropic' || (t.type === 'openai' && !!t.acceptAnthropic) : t.type !== 'anthropic');
  let usable = enabled.filter(acceptsProto);
  // 渠道专属网关密钥：锁定到单一渠道（禁用/无上游密钥/协议不匹配时快速失败，避免误路由到其他渠道）
  if (auth.targetId) {
    const bound = state.targets.find((t) => t.id === auth.targetId);
    if (!bound || bound.enabled === false) {
      return sendError(h, 403, 'target_disabled', '该专属 Key 绑定的渠道已禁用或不存在', { 'x-keypool-error': 'target_disabled' });
    }
    if (!(bound.keys || []).length) {
      return sendError(h, 503, 'no_upstream_keys', '该渠道尚未配置上游 API Key', { 'x-keypool-error': 'no_upstream_keys' });
    }
    if (!acceptsProto(bound)) {
      return sendError(
        h,
        400,
        'protocol_mismatch',
        bound.type === 'openai'
          ? '该渠道为 OpenAI 兼容型且未开启「接受 Anthropic 协议」，请在渠道设置中勾选后重试，或改用 /v1/chat/completions'
          : `该渠道类型为 ${bound.type}，不支持当前请求协议`,
        { 'x-keypool-error': 'protocol_mismatch' }
      );
    }
    usable = [bound];
  }
  if (!usable.length) {
    return sendError(h, 503, 'no_provider', '没有可用的 Provider（未配置或全部禁用）', { 'x-keypool-error': 'no_provider' });
  }

  let bodyBuf;
  try {
    bodyBuf = await readRequestBody(req, clampInt(s.maxBodyMB, 1, 1024, 100));
  } catch (e) {
    if (String(e.message) === 'body_too_large') return sendError(h, 413, 'body_too_large', '请求体过大');
    return sendError(h, 400, 'bad_request', '读取请求体失败: ' + e.message);
  }

  // 专属 Key 使用统计（按请求计）
  const grec = auth.record;
  if (grec) {
    if (!grec.stats) grec.stats = { requests: 0, success: 0, fail: 0, lastUsed: 0 };
    grec.stats.requests++;
    grec.stats.lastUsed = now();
    saveState();
  }

  // 请求体只解析一次：模型名与流式标记共用（原先同一 body 最多做 3 次全量 JSON.parse）
  let bodyJson = null;
  if (req.method === 'POST' && bodyBuf && bodyBuf.length) {
    try {
      bodyJson = JSON.parse(bodyBuf.toString('utf8'));
    } catch {}
  }
  const clientStream = !!(bodyJson && (bodyJson.stream === true || bodyJson.stream === 'true'));
  // 请求模型名（用于“密钥×模型”权限屏蔽过滤）：OpenAI/Anthropic 在 body.model，Gemini 在路径
  let reqModel = bodyJson && bodyJson.model ? String(bodyJson.model) : '';
  if (!reqModel) {
    const gm = /\/models\/([^/:]+)/.exec(pathname);
    if (gm) {
      try {
        reqModel = decodeURIComponent(gm[1]);
      } catch {
        reqModel = gm[1];
      }
    }
  }

  let candidates = [];
  for (const t of usable) for (const c of pickCandidates(t)) candidates.push(c);
  // 模型池路由：请求带模型名时，只在「模型池里有这个模型」的渠道内轮换，
  // 避免把 A 平台的模型发给 B 平台的 Key（白白多一次失败往返）。
  // 所有渠道池子里都没有该模型时保持全量轮换（池子可能过期，让上游给权威答复）。
  if (reqModel) {
    const want = normModelId(reqModel);
    const poolTargets = usable.filter((t) => targetHasModel(t, want));
    if (want && poolTargets.length && poolTargets.length < usable.length) {
      candidates = [];
      for (const t of poolTargets) for (const c of pickCandidates(t)) candidates.push(c);
      if (process.env.KEYPOOL_DEBUG) console.log(`[debug] 模型池路由 → ${poolTargets.map((t) => t.name).join(',')}`);
    }
  }
  // 模型权限过滤：优先只在未被标记“不支持该模型”的密钥中轮换；
  // 全部被标记时回退放行（让上游给出权威答复，同时刷新屏蔽表）
  const allowedC = candidates.filter((c) => !isModelBlocked(c.target.id, c.key.id, reqModel));
  if (allowedC.length) candidates = allowedC;
  if (process.env.KEYPOOL_DEBUG) {
    console.log(`[debug] ${pathname} t=${now()} candidates=${candidates.map((c) => `${maskKey(c.key.key)}(f=${c.entry.inFlight || 0},lu=${c.entry.lastUsed})`).join(',')}`);
  }
  if (!candidates.length) {
    const st = poolAvailableKeys();
    const retry = earliestCooldownSec();
    return sendError(h, 429, 'all_keys_cooling', `所有 API Key 均在冷却中或已禁用（可用 0，冷却 ${st.cooling}，禁用 ${st.disabled}），约 ${retry}s 后恢复，请稍后重试`, {
      'retry-after': String(retry),
      'x-keypool-error': 'all_cooling',
    });
  }

  // GET /v1/models：不同密钥可见的模型集合可能不同（按 Key 授权），
  // 这里跨密钥并发拉取并合并去重，保证客户端每次看到同一份完整列表
  if (req.method === 'GET' && /\/models$/.test(pathname)) {
    return await deliverModelsMerged(h, candidates, provider, pathname, grec, url);
  }

  // 并发占位模型：选中即记 lastUsed（并发请求自然轮到下一个 Key）；
  // 真正发起尝试时 inFlight+1，尝试处理完（含流式转发全程）后在 finally 中释放
  const attemptLimit = Math.max(1, Math.min(candidates.length, clampInt(s.maxAttempts, 1, 50, 6)));
  let lastErr = null;

  for (let i = 0; i < attemptLimit; i++) {
    const c = candidates[i];
    if (entryStatus(c.entry) !== 'ok') continue; // 前序尝试期间被熔断
    const started = now();
    c.entry.lastUsed = started;
    c.entry.inFlight = (c.entry.inFlight || 0) + 1;
    try {
      const r = await tryUpstream(c.target, c.key, provider, req, bodyBuf, pathname, clientStream ? 'raw' : 'text');
      if (r.ok) {
        const cType = r.headers.get('content-type') || '';
        let kind = classifyFailure(r.status, '', s);
        let text = null;
        if (kind === null && r.status >= 400) {
          // 4xx：读 body 后二次分类（invalid model field 等“密钥相关”错误可轮换）
          text = await readBodySafely(r.res);
          kind = classifyFailure(r.status, text, s);
        }
        if (kind !== null) {
          if (text === null) text = await readBodySafely(r.res);
          recordFailure(c.target, c.key, c.entry, kind, r.status, extractErrNote(text), r.headers, reqModel);
          lastErr = { kind, status: r.status, note: extractErrNote(text) };
          continue;
        }
        if (r.status >= 400) {
          // 非轮换类上游错误：原样透传给客户端
          if (text === null) text = await readBodySafely(r.res);
          recordFailure2Client(c.target, c.key, c.entry, r.status);
          if (grec) {
            grec.stats.fail++;
            saveState();
          }
          const out = { 'content-type': cType || 'application/json', 'x-keypool-target': c.target.name, 'x-keypool-key': maskKey(c.key.key) };
          h.writeHead(r.status, out);
          h.end(text);
          return;
        }
        // 成功
        recordSuccess(c.target, c.key, c.entry);
        if (grec) {
          grec.stats.success++;
          saveState();
        }
        addLog('info', `请求成功：${req.method} ${pathname} → ${c.target.name} ${maskKey(c.key.key)}（尝试 #${i + 1}，耗时 ${fmtMs(now() - started)}）`);
        return await deliverUpstream(h, req, r, c, bodyBuf, provider, pathname, started, clientStream);
      } else {
        recordFailure(c.target, c.key, c.entry, r.kind, 0, r.note);
        lastErr = { kind: r.kind, status: 0, note: r.note };
        continue;
      }
    } finally {
      c.entry.inFlight = Math.max(0, (c.entry.inFlight || 1) - 1);
    }
  }

  const st = poolAvailableKeys();
  if (grec) {
    grec.stats.fail++;
    saveState();
  }
  if (lastErr && lastErr.kind === 'model') {
    // 所有密钥都不支持该模型：这是客户端请求问题（模型名/权限），不是密钥故障，如实返回 400
    const msg = `该渠道所有密钥均不支持所请求模型：${lastErr.note}`;
    addLog('warn', `模型不可用：${pathname} — ${msg}`);
    return sendError(h, 400, 'model_not_supported', msg, { 'x-keypool-error': 'model_unsupported' });
  }
  const msg = lastErr
    ? `所有可用密钥均失败（${lastErr.kind}${lastErr.status ? ' ' + lastErr.status : ''}）：${lastErr.note}`
    : '没有可用密钥';
  addLog('error', `轮换耗尽：${pathname} — ${msg}`);
  return sendError(h, 502, 'all_keys_failed', msg, {
    'x-keypool-error': 'exhausted',
    'x-keypool-available': String(st.ok),
  });
}

function recordFailure2Client(target, keyRec, entry, status) {
  entry.lastUsed = now();
  entry.requests++;
  entry.fail++;
  entry.lastStatus = status;
  entry.lastError = 'upstream ' + status + ' (passthrough)';
}

async function deliverUpstream(h, req, r, c, bodyBuf, provider, pathname, started, clientStream) {
  const cType = r.headers.get('content-type') || '';
  const out = { 'content-type': cType || 'application/json' };
  const rid = r.headers.get('x-request-id') || r.headers.get('request-id') || r.headers.get('cf-ray') || '';
  if (rid) out['x-request-id'] = rid;
  out['x-keypool-target'] = c.target.name;
  out['x-keypool-key'] = maskKey(c.key.key);
  out['x-keypool-attempts'] = '1';

  const wantStream = state.settings.streamPassthrough && (cType.includes('text/event-stream') || clientStream);

  if (wantStream && r.res.body) {
    h.writeHead(r.status, out);
    h.flushHeaders(); // 首个上游分片到达前先把响应头发给客户端，压低首字感知延迟
    await pumpStream(h, req, r, c, started);
    return;
  }

  const text = await readBodySafely(r.res, 64 * 1024 * 1024);
  try {
    const j = safeJSON(text);
    if (j && j.usage) recordUsage(c.target, c.key, c.entry, j.usage, started);
  } catch {}
  h.writeHead(r.status, out);
  h.end(text);
}

async function pumpStream(h, req, r, c, started) {
  const idleMs = clampInt(state.settings.streamIdleTimeoutSeconds, 5, 3600, 120) * 1000;
  let idleTimer = setTimeout(() => {
    try {
      r.ctrl.abort(new Error('stream idle timeout'));
    } catch {}
  }, idleMs);
  const resetIdle = () => idleTimer.refresh();
  let tailBuf = Buffer.alloc(0); // 滚动缓冲，用于流结束时解析 usage
  let clientGone = false;
  const onClose = () => {
    clientGone = true;
  };
  req.on('close', onClose);
  try {
    for await (const chunk of r.res.body) {
      resetIdle();
      if (clientGone) break;
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      if (!h.writableEnded && !h.destroyed) h.write(buf);
      tailBuf = Buffer.concat([tailBuf, buf]);
      if (tailBuf.length > 2048) tailBuf = tailBuf.subarray(tailBuf.length - 2048);
    }
    const tailStr = tailBuf.toString('utf8');
    if (tailStr.includes('usage')) {
      const parts = tailStr.split(/data:\s*/);
      for (let i = parts.length - 1; i >= 0; i--) {
        const line = parts[i].split('\n')[0].trim();
        const j = safeJSON(line);
        if (j && j.usage) {
          recordUsage(c.target, c.key, c.entry, j.usage, started);
          break;
        }
      }
    }
    if (!clientGone && !h.writableEnded && !h.destroyed) h.end();
  } catch (e) {
    addLog('warn', `流式转发中断：${String((e && e.message) || e).slice(0, 200)}`);
  } finally {
    clearTimeout(idleTimer);
    req.removeListener('close', onClose);
    if (clientGone) {
      try {
        r.ctrl.abort(new Error('client disconnected'));
      } catch {}
    }
  }
}

/* ------------------------------ 管理后台 API ------------------------------ */

/* 登录失败限流（内存滑动窗口）：同一来源 15 分钟内失败 ≥5 次 → 锁 15 分钟。
 * 只拦 /admin/login，不影响网关；进程重启即清零。 */
const LOGIN_WINDOW_MS = 15 * 60000;
const LOGIN_MAX_FAILS = 5;
const loginFails = new Map(); // source -> { fails: number[], lockedUntil }
function loginSource(req) {
  const xf = req.headers['x-forwarded-for'];
  if (xf) return String(xf).split(',')[0].trim().slice(0, 64);
  return req.socket && req.socket.remoteAddress ? String(req.socket.remoteAddress).slice(0, 64) : 'unknown';
}
function loginLocked(src) {
  const rec = loginFails.get(src);
  if (!rec) return 0;
  if (rec.lockedUntil > now()) return Math.ceil((rec.lockedUntil - now()) / 1000);
  return 0;
}
function recordLoginFail(src) {
  let rec = loginFails.get(src);
  if (!rec) {
    rec = { fails: [], lockedUntil: 0 };
    loginFails.set(src, rec);
  }
  rec.fails = rec.fails.filter((t) => t > now() - LOGIN_WINDOW_MS);
  rec.fails.push(now());
  if (rec.fails.length >= LOGIN_MAX_FAILS) {
    rec.lockedUntil = now() + LOGIN_WINDOW_MS;
    rec.fails = [];
    addLog('warn', `来源 ${src} 登录连续失败 ${LOGIN_MAX_FAILS} 次，锁定 15 分钟`);
  }
  if (loginFails.size > 1000) {
    for (const [k, v] of loginFails) if (v.lockedUntil <= now() && !v.fails.length) loginFails.delete(k);
  }
}
function clearLoginFails(src) {
  loginFails.delete(src);
}

async function handleAdmin(h, req, url, pathname) {
  // 登录 / 初始化
  if (pathname === '/admin/login' && req.method === 'POST') {
    const src = loginSource(req);
    const lockSec = loginLocked(src);
    if (lockSec > 0) {
      addLog('warn', `来源 ${src} 登录被限流，剩余 ${lockSec}s`);
      return sendError(h, 429, 'too_many_attempts', `尝试次数过多，请 ${lockSec} 秒后再试`, { 'retry-after': String(lockSec) });
    }
    let body;
    try {
      body = JSON.parse((await readRequestBody(req, 1)).toString('utf8') || '{}');
    } catch {
      body = {};
    }
    const pwd = String(body.password || '');
    if (!state.adminPasswordHash) {
      if (pwd.length < 6) return sendError(h, 400, 'weak_password', '首次设置：密码至少 6 位');
      state.adminPasswordHash = sha256('kp:' + pwd);
      saveState(true);
      addLog('info', '管理密码已设置');
      clearLoginFails(src);
      return sendJSON(h, 200, { ok: true, token: adminTokenFor(), setup: true });
    }
    if (sha256('kp:' + pwd) !== state.adminPasswordHash) {
      recordLoginFail(src);
      return sendError(h, 401, 'unauthorized', '密码错误');
    }
    clearLoginFails(src);
    return sendJSON(h, 200, { ok: true, token: adminTokenFor() });
  }

  const adminPath = pathname.startsWith('/admin/api/') ? pathname.slice('/admin/api/'.length) : pathname === '/admin/api' ? '' : null;
  if (adminPath === null) {
    return sendError(h, 404, 'not_found', 'Not found');
  }

  if (!requireAdmin(h, req)) return;

  /* ---- 修改管理密码 ---- */
  if (adminPath === 'password' && req.method === 'POST') {
    let body;
    try {
      body = JSON.parse((await readRequestBody(req, 2)).toString('utf8') || '{}');
    } catch {
      body = {};
    }
    const oldP = String(body.oldPassword || '');
    const newP = String(body.newPassword || '');
    if (sha256('kp:' + oldP) !== state.adminPasswordHash) {
      return sendError(h, 400, 'wrong_password', '旧密码错误');
    }
    if (newP.length < 6) {
      return sendError(h, 400, 'weak_password', '新密码至少 6 位');
    }
    state.adminPasswordHash = sha256('kp:' + newP);
    saveState(true);
    addLog('info', '管理密码已在后台修改（旧会话令牌已失效）');
    return sendJSON(h, 200, { ok: true, token: adminTokenFor() });
  }

  /* ---- 概览 ---- */
  if (adminPath === 'overview' && req.method === 'GET') {
    const st = poolAvailableKeys();
    let totalReq = 0,
      totalOk = 0,
      totalFail = 0,
      pt = 0,
      ct = 0,
      curConcurrent = 0,
      peakConcurrent = 0;
    for (const e of keyStates.values()) {
      totalReq += e.requests;
      totalOk += e.success;
      totalFail += e.fail;
      pt += e.promptTokens;
      ct += e.completionTokens;
      curConcurrent += e.inFlight || 0;
      peakConcurrent = Math.max(peakConcurrent, e.inFlight || 0);
    }
    let gwKeys = 0,
      gwReq = 0,
      gwOk = 0;
    for (const t of state.targets) {
      for (const g of t.gatewayKeys || []) {
        gwKeys++;
        if (g.enabled !== false) {
          gwReq += (g.stats && g.stats.requests) || 0;
          gwOk += (g.stats && g.stats.success) || 0;
        }
      }
    }
    const minuteAgo = now() - 60000;
    let rpm = 0;
    for (const l of state.logs) {
      if (l.t < minuteAgo) break;
      if (l.level === 'info' && l.msg.includes('请求成功')) rpm++;
    }
    return sendJSON(h, 200, {
      targets: state.targets.length,
      enabledTargets: state.targets.filter((t) => t.enabled !== false).length,
      keys: st,
      totalRequests: totalReq,
      totalSuccess: totalOk,
      totalFail: totalFail,
      promptTokens: pt,
      completionTokens: ct,
      rpm,
      concurrent: curConcurrent,
      peakConcurrent,
      gatewayKeys: gwKeys,
      gatewayKeyRequests: gwReq,
      gatewayKeySuccess: gwOk,
      uptimeMs: now() - bootAt,
      version: '1.4.0',
    });
  }

  /* ---- Targets CRUD ---- */
  if (adminPath === 'targets' && req.method === 'GET') {
    return sendJSON(h, 200, { targets: state.targets.map(publicTarget) });
  }

  if (adminPath === 'targets' && req.method === 'POST') {
    let body;
    try {
      body = JSON.parse((await readRequestBody(req, 2)).toString('utf8') || '{}');
    } catch {
      body = {};
    }
    const t = defaultTarget();
    t.name = String(body.name || '').trim() || '未命名渠道';
    t.baseUrl = String(body.baseUrl || '').trim();
    t.type = ['openai', 'anthropic', 'gemini', 'azure'].includes(body.type) ? body.type : 'openai';
    t.enabled = body.enabled !== false;
    t.note = String(body.note || '');
    if (body.azureApiVersion) t.azureApiVersion = String(body.azureApiVersion);
    if (body.anthropicModel) t.anthropicModel = String(body.anthropicModel);
    if (body.testModel) t.testModel = String(body.testModel);
    t.acceptAnthropic = !!body.acceptAnthropic;
    t.chatOnly = body.chatOnly !== false;
    state.targets.push(t);
    saveState();
    addLog('info', `新增渠道：${t.name} (${t.type}) ${t.baseUrl}`);
    return sendJSON(h, 200, { ok: true, target: publicTarget(t) });
  }

  const mTarget = /^targets\/([^/]+)(?:\/(.*))?$/.exec(adminPath);
  if (mTarget) {
    const t = findTarget(mTarget[1]);
    if (!t) return sendError(h, 404, 'not_found', '渠道不存在');
    const sub = mTarget[2] || '';

    if (!sub && req.method === 'PUT') {
      let body;
      try {
        body = JSON.parse((await readRequestBody(req, 2)).toString('utf8') || '{}');
      } catch {
        body = {};
      }
      const oldBase = t.baseUrl;
      const oldType = t.type;
      if (body.name !== undefined) t.name = String(body.name).trim() || t.name;
      if (body.baseUrl !== undefined) t.baseUrl = String(body.baseUrl).trim();
      if (body.type !== undefined && ['openai', 'anthropic', 'gemini', 'azure'].includes(body.type)) t.type = body.type;
      if (body.enabled !== undefined) t.enabled = !!body.enabled;
      if (body.note !== undefined) t.note = String(body.note);
      if (body.azureApiVersion !== undefined) t.azureApiVersion = String(body.azureApiVersion);
      if (body.anthropicModel !== undefined) t.anthropicModel = String(body.anthropicModel);
      if (body.testModel !== undefined) t.testModel = String(body.testModel);
      if (body.acceptAnthropic !== undefined) t.acceptAnthropic = !!body.acceptAnthropic;
      if (body.chatOnly !== undefined) t.chatOnly = !!body.chatOnly;
      const baseChanged = t.baseUrl !== oldBase || t.type !== oldType;
      saveState();
      if (baseChanged) maybeRefreshPool(t, true);
      return sendJSON(h, 200, { ok: true, target: publicTarget(t) });
    }

    if (!sub && req.method === 'DELETE') {
      state.targets = state.targets.filter((x) => x.id !== t.id);
      saveState();
      addLog('info', `删除渠道：${t.name}`);
      return sendJSON(h, 200, { ok: true });
    }

    if (sub === 'keys' && req.method === 'POST') {
      let body;
      try {
        body = JSON.parse((await readRequestBody(req, 4)).toString('utf8') || '{}');
      } catch {
        body = {};
      }
      const lines = Array.isArray(body.keys) ? body.keys : String(body.keys || '').split(/\r?\n/);
      const added = addKeysToTarget(t, lines, parseInt(body.priority, 10) || 0, String(body.note || ''));
      saveState();
      addLog('info', `渠道 ${t.name} 新增 ${added.length} 个密钥`);
      if (added.length) maybeRefreshPool(t, true); // 加了 Key 就自动拉一次上游模型，填充模型池
      return sendJSON(h, 200, { ok: true, added: added.length, target: publicTarget(t) });
    }

    const mKey = /^keys\/([^/]+)$/.exec(sub);
    if (mKey) {
      const k = (t.keys || []).find((x) => x.id === mKey[1]);
      if (!k) return sendError(h, 404, 'not_found', '密钥不存在');
      if (req.method === 'PATCH' || req.method === 'PUT') {
        let body;
        try {
          body = JSON.parse((await readRequestBody(req, 2)).toString('utf8') || '{}');
        } catch {
          body = {};
        }
        if (body.enabled !== undefined) {
          k.enabled = !!body.enabled;
          const e = getEntry(t.id, k.id);
          if (k.enabled) {
            e.enabled = true;
            e.status = 'ok';
            e.coolingUntil = 0;
            e.failStreak = 0;
          } else {
            e.enabled = false;
            e.status = 'disabled';
          }
        }
        if (body.priority !== undefined) k.priority = parseInt(body.priority, 10) || 0;
        if (body.note !== undefined) k.note = String(body.note);
        if (body.resetStats) {
          const e = getEntry(t.id, k.id);
          e.requests = 0;
          e.success = 0;
          e.fail = 0;
          e.failStreak = 0;
          e.promptTokens = 0;
          e.completionTokens = 0;
        }
        saveState();
        return sendJSON(h, 200, { ok: true, target: publicTarget(t) });
      }
      if (req.method === 'DELETE') {
        t.keys = t.keys.filter((x) => x.id !== k.id);
        saveState();
        addLog('info', `删除密钥 ${maskKey(k.key)} @ ${t.name}`);
        return sendJSON(h, 200, { ok: true, target: publicTarget(t) });
      }
    }

    /* ---- 渠道专属网关密钥 ---- */
    if (sub === 'gateway-keys' && req.method === 'POST') {
      let body;
      try {
        body = JSON.parse((await readRequestBody(req, 4)).toString('utf8') || '{}');
      } catch {
        body = {};
      }
      let key = String(body.key || '').trim();
      if (!key) key = genGatewayKey(t.name);
      if (gatewayKeyTaken(key)) {
        return sendError(h, 409, 'duplicate_key', '该密钥已被占用（全局密钥或其他渠道专属 Key），请换一个');
      }
      const rec = {
        id: 'g-' + randomHex(6),
        key,
        enabled: true,
        note: String(body.note || ''),
        createdAt: now(),
        stats: { requests: 0, success: 0, fail: 0, lastUsed: 0 },
      };
      t.gatewayKeys = t.gatewayKeys || [];
      t.gatewayKeys.push(rec);
      saveState(true);
      addLog('info', `渠道 ${t.name} 新增专属网关密钥 ${maskKey(key)}`);
      return sendJSON(h, 200, { ok: true, record: rec });
    }

    const mGk = /^gateway-keys\/([^/]+)$/.exec(sub);
    if (mGk) {
      const g = (t.gatewayKeys || []).find((x) => x.id === mGk[1]);
      if (!g) return sendError(h, 404, 'not_found', '专属密钥不存在');
      if (req.method === 'PATCH' || req.method === 'PUT') {
        let body;
        try {
          body = JSON.parse((await readRequestBody(req, 2)).toString('utf8') || '{}');
        } catch {
          body = {};
        }
        if (body.regenerate) {
          let nk = genGatewayKey();
          let tries = 0;
          while (gatewayKeyTaken(nk) && tries++ < 5) nk = genGatewayKey();
          g.key = nk;
        } else if (body.key !== undefined) {
          const nk = String(body.key).trim();
          if (!nk) return sendError(h, 400, 'empty_key', '密钥不能为空');
          if (nk !== g.key && gatewayKeyTaken(nk)) {
            return sendError(h, 409, 'duplicate_key', '该密钥已被占用（全局密钥或其他渠道专属 Key），请换一个');
          }
          g.key = nk;
        }
        if (body.enabled !== undefined) g.enabled = !!body.enabled;
        if (body.note !== undefined) g.note = String(body.note);
        if (body.resetStats) g.stats = { requests: 0, success: 0, fail: 0, lastUsed: 0 };
        saveState(true);
        addLog('info', `渠道 ${t.name} 专属密钥已更新 ${maskKey(g.key)}`);
        return sendJSON(h, 200, { ok: true, record: g });
      }
      if (req.method === 'DELETE') {
        t.gatewayKeys = t.gatewayKeys.filter((x) => x.id !== g.id);
        saveState(true);
        addLog('info', `删除专属密钥 ${maskKey(g.key)} @ ${t.name}`);
        return sendJSON(h, 200, { ok: true });
      }
    }

    if (sub === 'test' && req.method === 'POST') {
      let body = {};
      try {
        body = JSON.parse((await readRequestBody(req, 2)).toString('utf8') || '{}');
      } catch {}
      const keyId = body.keyId;
      const results = [];
      const list = keyId ? (t.keys || []).filter((k) => k.id === keyId) : t.keys || [];
      // 测试与模型池刷新并行：一次操作同时得到密钥健康和最新模型列表
      const mp = refreshTargetModels(t);
      for (const k of list.slice(0, 200)) {
        results.push(await probeKey(t, k));
      }
      const mres = await mp;
      return sendJSON(h, 200, { ok: true, results, models: mres.models || [], modelsUpdatedAt: mres.updatedAt, modelsNote: mres.note });
    }

    /* ---- 渠道模型池 ---- */
    if (sub === 'models' && req.method === 'GET') {
      return sendJSON(h, 200, { models: t.models || [], updatedAt: t.modelsUpdatedAt || 0, note: t.modelsNote || '', chatOnly: t.chatOnly !== false, total: (t.models || []).length });
    }
    if (sub === 'models/refresh' && req.method === 'POST') {
      const r = await refreshTargetModels(t);
      return sendJSON(h, 200, Object.assign({ ok: true }, r));
    }
  }

  /* ---- 密钥状态 ---- */
  if (adminPath === 'keystates' && req.method === 'GET') {
    const out = [];
    for (const t of state.targets) {
      for (const k of t.keys || []) {
        const e = getEntry(t.id, k.id);
        out.push({
          targetId: t.id,
          keyId: k.id,
          status: entryStatus(e),
          enabled: k.enabled,
          coolingUntil: e.coolingUntil,
          coolingInSec: e.coolingUntil > now() ? Math.ceil((e.coolingUntil - now()) / 1000) : 0,
          inFlight: e.inFlight || 0,
          requests: e.requests,
          success: e.success,
          fail: e.fail,
          lastStatus: e.lastStatus,
          lastError: e.lastError,
          lastUsed: e.lastUsed,
          promptTokens: e.promptTokens,
          completionTokens: e.completionTokens,
        });
      }
    }
    return sendJSON(h, 200, { states: out });
  }

  /* ---- 日志 ---- */
  if (adminPath === 'logs' && req.method === 'GET') {
    return sendJSON(h, 200, { logs: state.logs.slice(0, 200).map((l) => ({ t: l.t, level: l.level, msg: l.msg, time: fmtTime(l.t) })) });
  }

  /* ---- 设置 ---- */
  if (adminPath === 'settings' && req.method === 'GET') {
    const s = Object.assign({}, state.settings);
    delete s.apiKeysHash;
    return sendJSON(h, 200, { settings: s, hasApiKeys: !!(state.settings.apiKeys && state.settings.apiKeys.length) });
  }
  if (adminPath === 'settings' && req.method === 'PUT') {
    let body;
    try {
      body = JSON.parse((await readRequestBody(req, 2)).toString('utf8') || '{}');
    } catch {
      body = {};
    }
    const s = state.settings;
    for (const k of ['streamPassthrough', 'rateCooldownSeconds', 'serverCooldownSeconds', 'networkCooldownSeconds', 'billingCooldownMinutes', 'requestTimeoutSeconds', 'streamIdleTimeoutSeconds', 'maxAttempts', 'maxBodyMB', 'billingKeywords', 'rotationStrategy', 'maxConcurrentPerKey']) {
      if (body[k] !== undefined) s[k] = body[k];
    }
    if (body.apiKeys !== undefined) {
      const list = Array.isArray(body.apiKeys) ? body.apiKeys : String(body.apiKeys).split(/\r?\n/);
      s.apiKeys = list.map((x) => String(x).trim()).filter(Boolean);
      keyCache.clear();
      keyCacheLoaded = false;
    }
    saveState(true);
    addLog('info', '设置已更新');
    return sendJSON(h, 200, { ok: true });
  }

  /* ---- 配置导出 / 导入（备份迁移用，含密钥请妥善保管） ---- */
  if (adminPath === 'export' && req.method === 'GET') {
    return sendJSON(h, 200, {
      app: 'key-pool',
      exportedAt: now(),
      state: {
        version: state.version,
        settings: state.settings,
        targets: state.targets,
      },
    });
  }
  if (adminPath === 'import' && req.method === 'POST') {
    let body;
    try {
      body = JSON.parse((await readRequestBody(req, 16)).toString('utf8') || '{}');
    } catch {
      return sendError(h, 400, 'bad_json', '导入内容不是合法 JSON');
    }
    const incoming = body.state || body;
    if (!incoming || !Array.isArray(incoming.targets)) {
      return sendError(h, 400, 'bad_format', '导入文件缺少 targets 字段');
    }
    state.targets = incoming.targets;
    for (const t of state.targets) {
      t.id = t.id || 'p-' + randomHex(6);
      t.name = t.name || '未命名渠道';
      t.keys = Array.isArray(t.keys) ? t.keys : [];
      t.gatewayKeys = Array.isArray(t.gatewayKeys) ? t.gatewayKeys : [];
      for (const k of t.keys) {
        k.enabled = k.enabled !== false;
        k.priority = k.priority || 0;
        k.note = k.note || '';
      }
      for (const g of t.gatewayKeys) {
        g.enabled = g.enabled !== false;
        g.note = g.note || '';
        if (!g.stats) g.stats = { requests: 0, success: 0, fail: 0, lastUsed: 0 };
      }
    }
    if (incoming.settings && typeof incoming.settings === 'object') {
      const merged = Object.assign(defaultState().settings, incoming.settings);
      merged.adminPasswordHash = state.adminPasswordHash; // 导入不改变管理密码
      state.settings = merged;
      keyCache.clear();
      keyCacheLoaded = false;
    }
    saveState(true);
    addLog('info', `导入配置完成：${state.targets.length} 个渠道`);
    return sendJSON(h, 200, { ok: true, targets: state.targets.length });
  }

  return sendError(h, 404, 'not_found', 'Unknown admin api');
}

/* ------------------------------ 密钥探测 ------------------------------ */

/* 版本号归一化：base 已以 /vN（如 /v1、/v1beta）结尾则原样返回，否则补上版本号。
 * 探测与转发必须使用同一规则，否则 base 带 /v1 的渠道会拼出 /v1/v1/... 导致全部 404。 */
function withVersion(base, version) {
  const b = String(base || '').trim().replace(/\/+$/, '');
  const re = new RegExp('/' + String(version).replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$', 'i');
  return re.test(b) ? b : b + '/' + version;
}

async function probeKey(t, k) {
  const started = now();
  const base = String(t.baseUrl || '').replace(/\/+$/, '');
  const item = { keyId: k.id, keyMask: maskKey(k.key), ok: false, status: 0, message: '' };
  const fetchT = async (url, opts) => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(new Error('timeout')), 30000);
    try {
      return await guardedFetch(url, Object.assign({}, opts, { signal: ctrl.signal }));
    } finally {
      clearTimeout(timer);
    }
  };
  try {
    let res;
    if (t.type === 'anthropic') {
      res = await fetchT(joinBase(withVersion(base, 'v1'), '/messages'), {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-api-key': k.key, 'anthropic-version': t.anthropicVersion || '2023-06-01' },
        body: JSON.stringify({ model: t.anthropicModel || 'claude-3-5-haiku-20241022', max_tokens: 1, messages: [{ role: 'user', content: 'hi' }] }),
      });
    } else if (t.type === 'gemini') {
      res = await fetchT(joinBase(withVersion(base, 'v1beta'), '/models') + '?pageSize=1&key=' + encodeURIComponent(k.key), { method: 'GET' });
    } else if (t.type === 'azure') {
      const dep = (t.keys || []).length && t.testModel ? t.testModel : 'gpt-4o-mini';
      res = await fetchT(
        joinBase(base, '/openai/deployments/' + encodeURIComponent(dep) + '/chat/completions') + '?api-version=' + encodeURIComponent(t.azureApiVersion || '2024-10-21'),
        {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'api-key': k.key },
          body: JSON.stringify({ messages: [{ role: 'user', content: 'hi' }], max_tokens: 1 }),
        }
      );
    } else {
      const nb = withVersion(base, 'v1');
      res = await fetchT(joinBase(nb, '/models'), { method: 'GET', headers: { authorization: 'Bearer ' + k.key } });
      if (res.status === 404 || res.status === 405) {
        res = await fetchT(joinBase(nb, '/chat/completions'), {
          method: 'POST',
          headers: { 'content-type': 'application/json', authorization: 'Bearer ' + k.key },
          body: JSON.stringify({ model: t.testModel || 'gpt-4o-mini', max_tokens: 1, messages: [{ role: 'user', content: 'hi' }] }),
        });
      }
    }
    item.status = res.status;
    const text = (await readBodySafely(res, 4096)).slice(0, 300);
    item.ok = res.status >= 200 && res.status < 300;
    item.message = item.ok ? 'OK' : extractErrNote(text);
    item.latencyMs = now() - started;
  } catch (e) {
    item.ok = false;
    item.message = String((e && e.message) || e).slice(0, 200);
    item.latencyMs = now() - started;
  }
  return item;
}

/* ------------------------------ 静态文件 ------------------------------ */

function serveStatic(h, pathname) {
  let rel = pathname === '/' || pathname === '/admin' || pathname === '/admin/' ? 'index.html' : pathname.replace(/^\/+/, '');
  const file = path.normalize(path.join(PUBLIC_DIR, rel));
  if (file !== PUBLIC_DIR && !file.startsWith(PUBLIC_DIR + path.sep)) return sendText(h, 403, 'forbidden');
  fs.readFile(file, (err, data) => {
    if (err) return sendText(h, 404, 'Not Found');
    const ext = path.extname(file).toLowerCase();
    const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
    h.writeHead(200, { 'content-type': types[ext] || 'application/octet-stream', 'cache-control': 'no-cache' });
    h.end(data);
  });
}

/* ------------------------------ 主服务 ------------------------------ */

const bootAt = now();

/* 无前缀 API 路径别名：客户端 base 填成 https://host（不带 /v1）时命中的路径，自动补 /v1 */
const API_PATH_ALIAS = {
  '/chat/completions': 1,
  '/completions': 1,
  '/embeddings': 1,
  '/responses': 1,
  '/moderations': 1,
  '/images/generations': 1,
  '/images/edits': 1,
  '/audio/speech': 1,
  '/audio/transcriptions': 1,
  '/audio/translations': 1,
  '/rerank': 1,
  '/models': 1,
  '/messages': 1,
  '/complete': 1,
};

const server = http.createServer(async (req, h) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  let pathname = url.pathname.replace(/\/+$/, '') || '/';
  /* 路径别名：客户端的 base 常填成 https://host（不带 /v1），请求就会打到 /models、
   * /chat/completions 这类无前缀路径。统一补上 /v1，避免"获取不到模型"这类困惑。 */
  if (!pathname.startsWith('/v1/') && !pathname.startsWith('/v1beta') && API_PATH_ALIAS[pathname]) {
    pathname = '/v1' + pathname;
  }

  try {
    /* 健康检查 */
    if (pathname === '/health' || pathname === '/admin/api/health') {
      const st = poolAvailableKeys();
      return sendJSON(h, 200, { ok: true, service: 'keypool', keys: st, uptimeMs: now() - bootAt });
    }
    if (pathname === '/favicon.ico') {
      h.writeHead(204);
      return h.end();
    }

    /* 管理后台 */
    if (pathname === '/' || pathname === '/admin' || pathname.startsWith('/assets/')) {
      return serveStatic(h, pathname === '/admin' ? '/' : pathname);
    }
    if (pathname === '/admin/login' || pathname.startsWith('/admin/api/')) {
      return await handleAdmin(h, req, url, pathname === '/admin/login' ? '/admin/login' : '/admin/api/' + pathname.slice('/admin/api/'.length).replace(/\/+$/, ''));
    }

    /* CORS 预检（网关路径）。max-age 让浏览器缓存预检结果，
     * 跨境/高 RTT 线路上省掉每次请求前的 OPTIONS 整轮往返 */
    if (req.method === 'OPTIONS') {
      h.writeHead(204, {
        'access-control-allow-origin': '*',
        'access-control-allow-methods': 'GET, POST, OPTIONS',
        'access-control-allow-headers': 'authorization, content-type, x-api-key, x-goog-api-key, anthropic-version, anthropic-beta',
        'access-control-max-age': '86400',
      });
      return h.end();
    }

    /* OpenAI 兼容网关 */
    const openaiPaths = {
      '/v1/chat/completions': 1,
      '/v1/completions': 1,
      '/v1/embeddings': 1,
      '/v1/responses': 1,
      '/v1/moderations': 1,
      '/v1/images/generations': 1,
      '/v1/images/edits': 1,
      '/v1/audio/speech': 1,
      '/v1/audio/transcriptions': 1,
      '/v1/audio/translations': 1,
      '/v1/rerank': 1,
    };
    if (req.method === 'POST' && openaiPaths[pathname]) {
      return await relayGateway(h, req, url, 'openai', pathname);
    }
    if (req.method === 'GET' && pathname === '/v1/models') {
      return await relayGateway(h, req, url, 'openai', pathname);
    }

    /* Anthropic 兼容网关 */
    if (req.method === 'POST' && (pathname === '/v1/messages' || pathname === '/v1/complete')) {
      return await relayGateway(h, req, url, 'anthropic', pathname);
    }
    if (req.method === 'GET' && pathname === '/v1/models' && req.headers['x-api-key'] && !req.headers['authorization']) {
      return await relayGateway(h, req, url, 'anthropic', pathname);
    }

    /* Gemini 兼容网关（原生路径透传） */
    if (pathname.startsWith('/v1beta/') && (req.headers['x-goog-api-key'] || url.searchParams.get('key'))) {
      return await relayGateway(h, req, url, 'openai', pathname);
    }

    return sendError(h, 404, 'not_found', `未知路径 ${req.method} ${pathname}，网关路径：/v1/chat/completions、/v1/models、/v1/messages 等（/v1 前缀可省略）`);
  } catch (e) {
    console.error('[keypool] handler error:', e);
    try {
      sendError(h, 500, 'internal', String((e && e.message) || e));
    } catch {}
  }
});

/* 服务端 keep-alive 延长到 65s（默认 5s）：客户端两次请求间隔一超就要重付整轮 TCP+TLS 握手，
 * 对外网客户端这是每请求几十到几百毫秒的固定首字开销。headersTimeout 需大于 keepAliveTimeout。 */
server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;
server.on('connection', (sock) => {
  try {
    sock.setNoDelay(true);
  } catch {}
});

/* 优雅退出 */
function shutdown() {
  console.log('[keypool] shutting down…');
  saveState(true);
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

loadState();
server.listen(PORT, HTTP_HOST, () => {
  console.log(`[keypool] 服务已启动: http://${HTTP_HOST}:${PORT}`);
  console.log(`[keypool] 管理后台:   http://${HTTP_HOST}:${PORT}/admin`);
  console.log(`[keypool] 数据目录:   ${DATA_DIR}`);
  console.log(`[keypool] 网关示例:   POST http://${HTTP_HOST}:${PORT}/v1/chat/completions`);
  if (!state.adminPasswordHash) console.log('[keypool] 首次使用请打开管理后台设置密码');
});

/* ------------------------------ 原生 HTTPS（自签证书直连部署） ------------------------------
 * 环境变量 / CLI：
 *   --tls-cert / KEYPOOL_TLS_CERT   证书路径（PEM）
 *   --tls-key  / KEYPOOL_TLS_KEY    私钥路径（PEM）
 *   --tls-port / KEYPOOL_TLS_PORT   HTTPS 监听端口（默认 443）
 *   --redirect-port / KEYPOOL_REDIRECT_PORT  HTTP 跳转 HTTPS 的端口（默认 80，绑定失败仅告警）
 *   --acme-webroot / KEYPOOL_ACME_WEBROOT    ACME HTTP-01 校验目录（默认 /etc/keypool/acme，
 *                                            80 端口对该路径直出文件、不跳转，供 acme.sh 免停机签发/续签）
 * 同时保留上面的 HTTP 监听（本机健康检查/管理用）。
 * 证书文件被替换（如 acme.sh 续签覆盖）后 60s 内自动热加载，无需重启进程。
 */
const tlsCertPath = argValue('tls-cert') || process.env.KEYPOOL_TLS_CERT || '';
const tlsKeyPath = argValue('tls-key') || process.env.KEYPOOL_TLS_KEY || '';
if (tlsCertPath && tlsKeyPath) {
  const tlsPort = parseInt(argValue('tls-port') || process.env.KEYPOOL_TLS_PORT || '443', 10);
  const acmeWebroot = argValue('acme-webroot') || process.env.KEYPOOL_ACME_WEBROOT || '/etc/keypool/acme';
  let tlsOpts;
  try {
    tlsOpts = { cert: fs.readFileSync(tlsCertPath), key: fs.readFileSync(tlsKeyPath) };
  } catch (e) {
    console.error(`[keypool] TLS 证书读取失败: ${e.message}（仅保留 HTTP 模式）`);
    tlsOpts = null;
  }
  if (tlsOpts) {
    const httpsServer = https.createServer(tlsOpts, (req, res) => server.emit('request', req, res));
    httpsServer.keepAliveTimeout = 65000;
    httpsServer.headersTimeout = 66000;
    httpsServer.on('connection', (sock) => {
      try {
        sock.setNoDelay(true);
      } catch {}
    });
    httpsServer.on('error', (e) => console.error(`[keypool] HTTPS 监听失败(${tlsPort}): ${e.message}`));
    httpsServer.listen(tlsPort, HOST, () => {
      console.log(`[keypool] HTTPS 已启动: https://${HOST}:${tlsPort}`);
    });
    // 证书热加载：acme.sh 续签只需覆盖文件，进程不重启、服务不断
    let tlsMtime = 0;
    try {
      tlsMtime = fs.statSync(tlsCertPath).mtimeMs + ':' + fs.statSync(tlsKeyPath).mtimeMs;
    } catch {}
    setInterval(() => {
      let m;
      try {
        m = fs.statSync(tlsCertPath).mtimeMs + ':' + fs.statSync(tlsKeyPath).mtimeMs;
      } catch {
        return;
      }
      if (m === tlsMtime) return;
      tlsMtime = m;
      try {
        httpsServer.setSecureContext({ cert: fs.readFileSync(tlsCertPath), key: fs.readFileSync(tlsKeyPath) });
        console.log('[keypool] TLS 证书已热加载（续签生效，无需重启）');
      } catch (e) {
        console.error(`[keypool] TLS 证书热加载失败: ${e.message}`);
      }
    }, 60000).unref();
    // HTTP 80 → HTTPS 跳转（可选）；ACME HTTP-01 校验路径直出文件
    const redirectPort = parseInt(argValue('redirect-port') || process.env.KEYPOOL_REDIRECT_PORT || '80', 10);
    if (redirectPort > 0) {
      const ACME_PREFIX = '/.well-known/acme-challenge/';
      const redirectServer = http.createServer((req, res) => {
        const p = decodeURIComponent((req.url || '/').split('?')[0]);
        if (p.startsWith(ACME_PREFIX)) {
          // 只允许 token 字符集，杜绝路径穿越；文件按 webroot/<原路径> 查找（与 acme.sh -w 约定一致）
          const rel = p.slice(1);
          if (!/^[\w.\-\/]+$/.test(rel) || rel.includes('..')) {
            res.writeHead(400, { 'content-type': 'text/plain' });
            return res.end('bad challenge path');
          }
          const token = p.slice(ACME_PREFIX.length).replace(/[^A-Za-z0-9_.\-]/g, '');
          try {
            const body = fs.readFileSync(require('path').join(acmeWebroot, ACME_PREFIX.slice(1), token))
              .toString('utf8');
            res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
            return res.end(body);
          } catch {
            res.writeHead(404, { 'content-type': 'text/plain' });
            return res.end('challenge not found');
          }
        }
        const host = (req.headers.host || '').split(':')[0] || HOST;
        res.writeHead(301, { Location: `https://${host}${req.url}` });
        res.end();
      });
      redirectServer.on('error', () => {}); // 80 被占用时静默跳过
      redirectServer.listen(redirectPort, HOST, () => {
        console.log(`[keypool] HTTP ${redirectPort} → HTTPS 跳转已启动（ACME 校验目录 ${acmeWebroot}）`);
      });
    }
  }
}
