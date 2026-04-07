// ===================== 全局配置 =====================
const PROXY_DOMAIN_SUFFIX = 'example.com'; // 替换为你的主域名
const ENTRY_DOMAIN = 'gh.' + PROXY_DOMAIN_SUFFIX;
const PROXY_LABEL_PREFIX = 'p';
const PROXY_LABEL_SUFFIX = '-gh';

const ENABLE_GEO_REDIRECT = true;
const ALLOWED_COUNTRIES = ['CN'];
const ENABLE_STRICT_DEFENSE = true;

const SENSITIVE_QUERY_PARAMS = ['return_to', 'redirect_to', 'next', 'continue', 'destination'];
const SENSITIVE_URL_PARAMS = ['access_token', 'token'];
const SENSITIVE_REQ_HEADERS = [
  'authorization',
  'x-forwarded-host',
  'x-forwarded-proto',
  'cf-connecting-ip',
  'cf-ipcountry',
  'cf-ray',
  'cf-visitor',
  'x-forwarded-for',
  'x-real-ip',
];

const STRIP_RESP_HEADERS = [
  'content-security-policy',
  'content-security-policy-report-only',
  'clear-site-data',
  'x-frame-options',
  'content-length', // 内容经过改写，原始 content-length 不再准确
];

const MAX_REWRITE_SIZE = 5 * 1024 * 1024; // 5MB
const UPSTREAM_TIMEOUT_MS = 15000;
const ENABLE_CACHE = true; // 启用 Cache API 缓存层，减少上游请求
const CACHE_TTL = 300; // 缓存默认 TTL（秒），仅在上游无明确 Cache-Control 时使用

const ALLOWED_COOKIES = new Set(['_gh_sess', '_octo']);
const MAX_COOKIE_VALUE_LENGTH = 512;

// ===================== 域名白名单 =====================
/**
 * 自动映射生成：只需维护白名单，映射规则自动计算。
 *
 * 这里使用“短标签 + 确定性哈希”而不是数组索引或原始域名直出：
 *   raw.githubusercontent.com -> p<stable-hash>-gh.example.com
 *
 * 特点：
 * 1. 同一个原始域名永远映射到同一个代理域名。
 * 2. 以后新增白名单项时，已有映射不会因为顺序变化而漂移。
 * 3. 同时保留正向和反向静态映射，便于请求转发和重定向改写。
 * 4. 代理子域不暴露 github / githubusercontent 等敏感关键词，降低
 *    被浏览器或安全产品误判为钓鱼镜像的概率。
 */
const domain_whitelist = [
  // 核心
  'github.com',
  'api.github.com',
  'gist.github.com',

  // 静态资源
  'github.githubassets.com',
  'assets-cdn.github.com',
  'cdn.jsdelivr.net',
  'github.global.ssl.fastly.net',

  // 下载
  'codeload.github.com',
  'git-lfs.github.com',

  // githubusercontent（公共内容）
  'githubusercontent.com',
  'raw.githubusercontent.com',
  'gist.githubusercontent.com',
  'avatars.githubusercontent.com',
  'camo.githubusercontent.com',
  'objects.githubusercontent.com',
  'media.githubusercontent.com',
  'cloud.githubusercontent.com',
  'user-images.githubusercontent.com',
  'favicons.githubusercontent.com',
  'repository-images.githubusercontent.com',
  'render.githubusercontent.com',

  // GitHub 子站（全部公开访问）
  'docs.github.com',
  'education.github.com',
  'securitylab.github.com',
  'desktop.github.com',
  'pages.github.com',

  // 状态页
  'www.githubstatus.com',

  // NPM（公开访问）
  'npmjs.com',
  'api.npms.io',
];

function buildStaticProxyLabel(domain) {
  return `${PROXY_LABEL_PREFIX}${stableDomainHash(stripPort(domain))}${PROXY_LABEL_SUFFIX}`;
}

function buildStaticProxyHost(domain) {
  return `${buildStaticProxyLabel(domain)}.${PROXY_DOMAIN_SUFFIX}`;
}

function stableDomainHash(input) {
  let hash = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;

  for (const ch of input) {
    hash ^= BigInt(ch.codePointAt(0));
    hash = (hash * prime) & 0xffffffffffffffffn;
  }

  const short = hash & 0xFFFFFn;
  return short.toString(36).padStart(4, '0');
}

function buildStaticDomainEntries(domains) {
  const entries = [];
  const labelToOrigin = new Map();

  for (const rawDomain of domains) {
    const domain = stripPort(rawDomain);
    const label = buildStaticProxyLabel(domain);
    const existing = labelToOrigin.get(label);

    if (existing && existing !== domain) {
      throw new Error(`Static proxy label collision: ${existing} and ${domain} -> ${label}`);
    }

    labelToOrigin.set(label, domain);
    entries.push([domain, label]);
  }

  return entries;
}

const static_domain_entries = buildStaticDomainEntries(domain_whitelist);

// 原始域名 -> 稳定标签（不含主域名）
const domain_proxy_labels = Object.fromEntries(static_domain_entries);

// 稳定标签 -> 原始域名
const reverse_proxy_labels = Object.fromEntries(
  static_domain_entries.map(([domain, label]) => [label, domain])
);

// 原始域名 -> 完整代理域名
const domain_mappings = Object.fromEntries(
  static_domain_entries.map(([domain, label]) => [
    domain,
    `${label}.${PROXY_DOMAIN_SUFFIX}`,
  ])
);

// 完整代理域名 -> 原始域名
const reverse_mappings = Object.fromEntries(
  static_domain_entries.map(([domain, label]) => [
    `${label}.${PROXY_DOMAIN_SUFFIX}`,
    domain,
  ])
);

// ===================== 预编译正则 =====================

// 预先构建合并正则，统一处理文本响应中的白名单域名替换。

/**
 * 按原始域名长度降序排列，确保正则交替分支优先匹配更具体的域名
 */
const domainsByLength = Object.keys(domain_mappings).sort((a, b) => b.length - a.length);

function escapeRegExpLiteral(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const mergedDomainPattern = domainsByLength.map(escapeRegExpLiteral).join('|');

/**
 * 合并正则：一次扫描替换所有域名
 * 捕获组 1 = 协议部分（可能为空），捕获组 2 = 匹配到的原始域名
 */
const mergedDomainRe = new RegExp(
  `(https?:)?//(${mergedDomainPattern})(?=[/"'\\s);>,\\]}&]|$)`,
  'g'
);

const jsonSafeRe = new RegExp(
  `https://(${mergedDomainPattern})(?=[/"'\\s);>,\\]}&]|$)`,
  'g'
);

// ===================== 敏感路径 =====================

const githubRedirectPatterns = [

  /^\/login/i,
  /^\/signup/i,
  /^\/join/i,
  /^\/sessions?/i,
  /^\/password_reset/i,
  /^\/account(\/|$)/i,
  /^\/settings(\/|$)/i,
  /^\/dashboard(\/|$)/i,
  /^\/notifications(\/|$)/i,
  /^\/pulls(\/|$)/i,
  /^\/issues(\/|$)/i,
  /^\/stars(\/|$)/i,
  /^\/watching(\/|$)/i,
  /^\/new(\/|$)/i,
  /^\/repos(\/|$)/i,
  /^\/orgs\/new(\/|$)/i,
  /^\/orgs\/[^\/]+\/(settings|billing|invitations|audit-log|blocked_users|member-privileges|policies|custom-repository-roles)(\/|$)/i,
  /^\/organizations(\/|$)/i,
  /^\/teams(\/|$)/i,
  /^\/billing(\/|$)/i,
  /^\/payments(\/|$)/i,
  /^\/discussions(\/|$)/i,
  /^\/projects(\/|$)/i,
  /^\/codespaces(\/|$)/i,
  /^\/(?:github-)?copilot\/.+/i,
  /^\/enterprise\/.+/i,
  /^\/spark(\/|$)/i,

  // GitHub 营销/产品页
  /^\/features(?:\/|$)/i,
  /^\/security\/advanced-security(\/|$)/i,
  /^\/solutions(?:\/|$)/i,
  /^\/enterprise\/startups(\/|$)/i,
  /^\/resources\//i,
  /^\/learn\/pathways(\/|$)/i,
  /^\/customer-stories(\/|$)/i,
  /^\/partners(\/|$)/i,
  /^\/(?:open-source\/sponsors|readme|topics|trending|collections)(\/|$)/i,
  /^\/(?:pricing|why-github|sponsors|marketplace|mcp)(\/|$)/i,
  /^\/(?:enterprise|team)(\/|$)/i,
  /^\/favicons\/favicon\.(?:svg|png)$/i,

];

const extraDefensePatterns = [
  // WordPress
  /^\/wp-(?:admin|login|signup|register|cron|comments-post|links-opml|json|config|content|includes)/i,
  /^\/xmlrpc\.php$/i,

  // Joomla / Drupal
  /^\/administrator(?:\/|$)/i,
  /^\/joomla(\/|$)/i,
  /^\/user(?:\/(?:login|register|password))?(\/|$)/i,
  /^\/(?:core\/install|update)\.php$/i,
  /^\/sites\/default\//i,

  // 通用后台
  /^\/(?:index\.php\/)?admin(?:\/|$)/i,
  /^\/(?:admincp|admin-panel|backend|manage|manager|cms|console|controlpanel|webadmin|cpanel)(\/|$)/i,
  /^\/(?:login|admin)\.php$/i,

  // 数据库
  /^\/(?:phpmyadmin|phpMyAdmin|pma|mysql|sql|dbadmin|myadmin)(\/|$)/i,

  // 探测文件
  /^\/(?:phpinfo|info|test|phpmyinfo|phptest)\.php$/i,
  /^\/(?:config|database|db)\.php/i,
  /^\/(?:backup|dump|shell|wshell)\.php$/i,
  /^\/[a-z0-9_\-]*shell\.php$/i,
  /^\/\.env/i,

  // 框架
  /^\/(?:laravel|thinkphp|vendor|_debugbar)(\/|$)/i,
  /^\/storage(?:\/logs)?(\/|$)/i,
  /^\/bootstrap\/cache\//i,
  /^\/(?:actuator|jolokia|druid|hydra|jmx-console|admin-console)(\/|$)/i,

  // DevOps
  /^\/(?:jenkins|hudson|gitlab|kibana|grafana|nagios|zabbix)(\/|$)/i,

  // 版本控制
  /^\/\.(?:git|svn|hg|idea|vscode)(?:\/|$)/i,
  /^\/(?:composer\.(?:json|lock)|package\.json|yarn\.lock)$/i,

  // 备份文件
  /^\/(?:backup|backups?|dump|dumps?|db(?:backup|dump)?)(\/|$)/i,
  /^\/[^\/]+\.(?:sql|sqlite|db|dump|gz|zip|7z|rar|tar(?:\.gz)?|bak|old|swp)$/i,

  // 服务器状态
  /^\/server-(?:status|info)(\/|$)/i,
  /^\/(?:_cluster\/health|elasticsearch)(\/|$)/i,
  /^\/(?:owa|ecp|Autodiscover|remote|vpn)(\/|$)/i,
  /^\/cgi-bin(?:\/.+)?(\/|$)/i,

];

// ===================== CORS =====================
function corsHeaders(origin) {
  const h = {
    'access-control-allow-methods': 'GET, HEAD, OPTIONS',
    'access-control-allow-headers': '*',
    'access-control-expose-headers': '*',
    'access-control-max-age': '86400',
  };
  if (origin) {
    h['access-control-allow-origin'] = origin;
    h['access-control-allow-credentials'] = 'true';
  } else {
    h['access-control-allow-origin'] = '*';
  }
  return h;
}

function appendVaryHeader(headers, value) {
  const current = headers.get('vary');
  if (!current) {
    headers.set('vary', value);
    return;
  }

  const needle = value.toLowerCase();
  const parts = current.split(',').map(v => v.trim().toLowerCase());
  if (!parts.includes(needle)) {
    headers.set('vary', `${current}, ${value}`);
  }
}

function applyCorsHeaders(headers, origin) {
  for (const [k, v] of Object.entries(corsHeaders(origin))) {
    headers.set(k, v);
  }
  if (origin) appendVaryHeader(headers, 'Origin');
  return headers;
}

function htmlResponse(html, status, origin) {
  const headers = new Headers({ 'content-type': 'text/html; charset=utf-8' });
  applyCorsHeaders(headers, origin);
  return new Response(html, {
    status,
    headers,
  });
}

// ===================== 工具函数 =====================
function stripPort(host) {
  return (host || '').toLowerCase().split(':')[0];
}

function getOriginByProxyLabel(label) {
  return reverse_proxy_labels[stripPort(label)] || null;
}

function getProxyHostByOrigin(origin) {
  const domain = stripPort(origin);
  return domain_proxy_labels[domain] ? buildStaticProxyHost(domain) : null;
}

function getProxyPrefix(host) {
  const h = stripPort(host);
  if (reverse_mappings[h]) return h;

  const suffix = `.${PROXY_DOMAIN_SUFFIX}`;
  if (!h.endsWith(suffix)) return null;

  const label = h.slice(0, -suffix.length);
  return getOriginByProxyLabel(label) ? h : null;
}

function getOriginByPrefix(prefix) {
  const h = stripPort(prefix);
  if (reverse_mappings[h]) return reverse_mappings[h];

  const suffix = `.${PROXY_DOMAIN_SUFFIX}`;
  if (!h.endsWith(suffix)) return null;

  const label = h.slice(0, -suffix.length);
  return getOriginByProxyLabel(label);
}

function findMappingForHost(host) {
  const h = stripPort(host);
  if (!h) return null;

  if (getProxyHostByOrigin(h)) return h;

  if (h.startsWith('www.')) {
    const h2 = h.slice(4);
    if (getProxyHostByOrigin(h2)) return h2;
  }

  // 仅允许精确命中白名单，避免把任意子域名误判为可代理目标。
  return null;
}

function normalizeToOriginHost(host) {
  const h = stripPort(host);
  if (!h) return null;

  if (getProxyHostByOrigin(h)) return h;

  if (h.startsWith('www.')) {
    const h2 = h.slice(4);
    if (getProxyHostByOrigin(h2)) return h2;
  }

  const prefix = getProxyPrefix(h);
  return prefix ? getOriginByPrefix(prefix) : null;
}

function mergeSearch(outer, inner) {
  const outerStr = (outer || '').replace(/^\?/, '');
  const innerStr = (inner || '').replace(/^\?/, '');

  if (!outerStr && !innerStr) return '';

  const merged = new URLSearchParams(innerStr);
  const outerParams = new URLSearchParams(outerStr);

  for (const [key, value] of outerParams) {
    merged.set(key, value);
  }

  const result = merged.toString();
  return result ? '?' + result : '';
}

function shouldRedirectGithubProxyRootToEntry(request, pathname, currentOrigin) {
  if (currentOrigin !== 'github.com') return false;
  if (pathname !== '/') return false;
  if (!['GET', 'HEAD'].includes(request.method)) return false;

  const accept = (request.headers.get('accept') || '').toLowerCase();
  return accept.includes('text/html');
}

// 递归解码并规范化路径，减少双重编码和冗余路径片段的影响。
function safeDecodeURI(str) {
  let prev = str;
  let decoded = str;
  const maxIterations = 5;
  for (let i = 0; i < maxIterations; i++) {
    try {
      decoded = decodeURIComponent(prev);
    } catch (_) {
      return prev;
    }
    if (decoded === prev) break;
    prev = decoded;
  }

  // 通过 URL 构造器规范化路径，消除 ../ 和冗余斜杠
  try {
    decoded = new URL(decoded, 'https://dummy').pathname;
  } catch (_) {
    // 如果无法解析，返回解码后的原始值
  }

  return decoded;
}

// ===================== 路径解析 =====================

// 从代理路径中提取目标域名、路径和查询参数。
function extractTargetFromPath(pathname) {
  if (!pathname || pathname === '/') return null;

  const tries = [pathname];
  try {
    const dec = decodeURIComponent(pathname);
    if (dec !== pathname) tries.unshift(dec);
  } catch (_) {}

  for (const p of tries) {
    const mProto = p.match(/^\/(https?):\/\/([^\/?#]+)(\/[^?#]*)?(\?.*)?$/i);
    if (mProto) {
      const origin = normalizeToOriginHost(mProto[2]);
      if (origin) return { target_host: origin, pathname: mProto[3] || '/', search: mProto[4] || '' };
    }

    const mSeg = p.match(/^\/([^\/?#]+)(\/[^?#]*)?(\?.*)?/);
    if (mSeg) {
      const segment = mSeg[1];
      // 基本域名格式校验：必须包含至少一个 '.'
      if (!segment.includes('.')) continue;
      const origin = normalizeToOriginHost(segment);
      if (origin) return { target_host: origin, pathname: mSeg[2] || '/', search: mSeg[3] || '' };
    }
  }
  return null;
}

// 修正 commit 信息接口中被拼接进 pathname 的完整 URL。
function fixCommitInfoPath(pathname) {
  const pattern = /(\/[^\/]+\/[^\/]+\/(?:latest-commit|tree-commit-info)\/[^\/]+)\/(https?(?:%3A|:)\/\/[^/]+\/[^/]+\/[^/]+\/.*)/i;
  const match = pathname.match(pattern);
  if (!match) return pathname;
  const prefix = match[1];
  const raw = match[2].includes('%3A') ? decodeURIComponent(match[2]) : match[2];
  let parsedUrl;
  try {
    parsedUrl = new URL(raw);
  } catch (err) {
    // 忽略无效格式导致的解析错误，避免在日志中产生过多噪音
    return pathname;
  }
  const segments = parsedUrl.pathname.split('/').slice(3).join('/');
  return segments ? `${prefix}/${segments}` : prefix;
}

// ===================== 缓存策略 =====================
function computeCacheControl(contentType, upstreamCacheControl) {
  const ct = (contentType || '').toLowerCase();
  const upCC = (upstreamCacheControl || '').toLowerCase();

  if (upCC.includes('no-store') || upCC.includes('no-cache') || upCC.includes('private')) {
    return 'no-store, no-cache, must-revalidate';
  }

  if (ct.includes('application/json')) {
    return 'public, max-age=60, s-maxage=60';
  }
  if (ct.includes('text/html')) {
    return 'public, max-age=300, s-maxage=300';
  }
  if (ct.includes('javascript') || ct.includes('text/css')) {
    return 'public, max-age=86400, s-maxage=86400';
  }
  if (ct.includes('image/') || ct.includes('font/') || ct.includes('application/octet-stream')) {
    return 'public, max-age=86400, s-maxage=86400';
  }
  return 'public, max-age=14400';
}

// ===================== 地理重定向 =====================
function tryGeoRedirect(request, currentOrigin, url) {
  if (!ENABLE_GEO_REDIRECT) return null;

  const country = (request.headers.get('CF-IPCountry') || '').toUpperCase();
  if (!country) return null;
  if (ALLOWED_COUNTRIES.includes(country)) return null;

  const originalUrl = new URL(url);
  originalUrl.protocol = 'https:';
  originalUrl.host = currentOrigin;
  return Response.redirect(originalUrl.href, 302);
}

// ===================== 响应改写 =====================

// 按内容类型改写响应正文中的域名引用，并为大文本响应提供限长保护。
async function modifyResponse(response) {
  const ct = response.headers.get('content-type') || '';

  // 非文本类响应直接透传
  if (!/text\/|application\/(json|javascript|xml)/i.test(ct)) {
    return response.body;
  }

  // 超过大小阈值的响应直接透传，避免 OOM
  const contentLengthHeader = response.headers.get('content-length');
  const contentLength = Number.parseInt(contentLengthHeader || '', 10);
  if (Number.isFinite(contentLength) && contentLength > MAX_REWRITE_SIZE) {
    return response.body;
  }

  let text;
  if (Number.isFinite(contentLength) && contentLength >= 0) {
    text = await response.text();
  } else {
    const probe = await readTextWithinLimit(response, MAX_REWRITE_SIZE);
    if (probe.exceeded) {
      return response.body;
    }
    text = probe.text;
    try {
      await response.body?.cancel();
    } catch (_) {}
  }

  const isJson = ct.includes('application/json');

  if (isJson) {
    // JSON 中仅替换带完整协议的 URL，降低误改 JSON 值的风险
    text = text.replace(jsonSafeRe, (_match, domain) => {
      const proxy = domain_mappings[domain];
      return proxy ? `https://${proxy}` : _match;
    });
  } else {
    // HTML / JS / XML / CSS：替换所有形式的域名引用
    text = text.replace(mergedDomainRe, (_match, proto, domain) => {
      const proxy = domain_mappings[domain];
      if (!proxy) return _match;
      return `${proto || ''}//${proxy}`;
    });
  }

  return text;
}

async function readTextWithinLimit(response, maxBytes) {
  const probe = response.clone();
  const reader = probe.body?.getReader();
  if (!reader) {
    return { exceeded: false, text: await probe.text() };
  }

  const decoder = new TextDecoder();
  let total = 0;
  let text = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    total += value.byteLength;
    if (total > maxBytes) {
      try {
        await reader.cancel();
      } catch (_) {}
      return { exceeded: true, text: '' };
    }

    text += decoder.decode(value, { stream: true });
  }

  text += decoder.decode();
  return { exceeded: false, text };
}

// 仅保留匿名访问所需的 Cookie，并限制单个值长度。
function sanitizeCookies(rawCookie) {
  if (!rawCookie) return '';

  return rawCookie
    .split(';')
    .map(c => c.trim())
    .filter(c => {
      const eqIdx = c.indexOf('=');
      if (eqIdx === -1) return false;
      const name = c.slice(0, eqIdx).trim().toLowerCase();
      const value = c.slice(eqIdx + 1);

      if (!ALLOWED_COOKIES.has(name)) return false;
      if (value.length > MAX_COOKIE_VALUE_LENGTH) return false;

      return true;
    })
    .join('; ');
}

// 删除跳转类和 token 类查询参数，避免敏感信息继续向上游传递。
function sanitizeSearchParams(searchStr) {
  if (!searchStr) return '';

  const params = new URLSearchParams(searchStr.replace(/^\?/, ''));
  let modified = false;

  for (const param of [...SENSITIVE_URL_PARAMS, ...SENSITIVE_QUERY_PARAMS]) {
    if (params.has(param)) {
      params.delete(param);
      modified = true;
    }
  }

  const result = params.toString();
  return result ? '?' + result : '';
}

function hasSensitiveQueryParam(searchStr) {
  if (!searchStr) return false;

  const params = new URLSearchParams(searchStr.replace(/^\?/, ''));
  for (const param of SENSITIVE_QUERY_PARAMS) {
    const value = params.get(param);
    if (value && githubRedirectPatterns.some(re => re.test(value))) {
      return true;
    }
  }
  return false;
}

// ===================== 页面模板 =====================
const COMMON_CSS = `
:root {
  --global-font-size: 15px;
  --global-line-height: 1.6;
  --global-font-family: "SF Mono", "Fira Code", "Consolas", "Monaco", "Courier New", monospace;
  --background-color: #0c0c0c;
  --font-color: #00ff41;
  --invert-font-color: #0c0c0c;
  --primary-color: #00ff41;
  --secondary-color: #008f11;
  --error-color: #ff0040;
  --progress-bar-background: #1a1a1a;
  --progress-bar-fill: #00ff41;
  --code-bg-color: #1a1a1a;
  --block-background-color: #1a1a1a;
  --input-style: solid;
  --input-border-width: 1px;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  background-color: var(--background-color);
  color: var(--font-color);
  min-height: 100vh;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  font-family: var(--global-font-family);
}

.container {
  width: 100%;
  max-width: 720px;
  padding: 2rem;
}

.terminal-window {
  border: 1px solid;
  background: #0a0a0a;
  border-radius: 4px;
  overflow: hidden;
}

.terminal-header {
  background: #1a1a1a;
  padding: 0.5rem 1rem;
  border-bottom: 1px solid;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.terminal-btn {
  width: 12px;
  height: 12px;
  border-radius: 50%;
  border: 1px solid;
}

.terminal-btn.close { background: #ff5f56; border-color: #e0443e; }
.terminal-btn.minimize { background: #ffbd2e; border-color: #dea123; }
.terminal-btn.maximize { background: #27c93f; border-color: #1aab29; }

.terminal-title {
  margin-left: auto;
  margin-right: auto;
  font-size: 12px;
  color: #666;
}

.terminal-body {
  padding: 2rem;
  text-align: center;
}

.prompt-line {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 1rem;
  text-align: left;
}

.prompt {
  color: var(--primary-color);
  white-space: nowrap;
}

.prompt-user { color: #00a8ff; }
.prompt-host { color: #00ff41; }
.prompt-path { color: #ffbd2e; }

.error-code {
  font-size: clamp(80px, 15vw, 140px);
  font-weight: bold;
  color: var(--error-color);
  line-height: 1;
  margin: 1rem 0;
  text-shadow: 0 0 20px rgba(255, 0, 64, 0.3);
  font-family: var(--global-font-family);
  letter-spacing: -5px;
}

.error-code::before { content: "["; color: #444; }
.error-code::after { content: "]"; color: #444; }

.error-title {
  font-size: 1.5rem;
  color: var(--error-color);
  margin: 0 0 1rem 0;
}

.error-subtitle {
  color: #888;
  margin: 0 0 2rem 0;
  font-size: 14px;
}

.error-details {
  background: #1a1a1a;
  border: 1px solid #333;
  padding: 1rem;
  margin: 1.5rem 0;
  text-align: left;
  font-size: 13px;
}

.error-details .line {
  display: flex;
  gap: 1rem;
}

.error-details .line-num {
  color: #444;
  min-width: 30px;
  text-align: right;
}

.error-details .line-content { color: #888; }
.error-details .line-content.error { color: var(--error-color); }

.back-btn {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  background: transparent;
  color: var(--primary-color);
  border: 1px solid var(--primary-color);
  padding: 0.75rem 1.5rem;
  font-family: var(--global-font-family);
  font-size: 14px;
  text-decoration: none;
  cursor: pointer;
  transition: all 0.2s;
  margin-top: 1rem;
}

.back-btn:hover {
  background: var(--primary-color);
  color: var(--invert-font-color);
}

.ascii-art {
  color: var(--error-color);
  font-size: 10px;
  line-height: 1.2;
  margin: 1rem 0;
  white-space: pre;
  opacity: 0.6;
}

.cursor {
  display: inline-block;
  width: 10px;
  height: 18px;
  background: var(--primary-color);
  animation: blink 1s step-end infinite;
  vertical-align: middle;
  margin-left: 2px;
}
.cursor.error {
  background: var(--error-color);
}

@keyframes blink { 50% { opacity: 0; } }

.footer {
  margin-top: 2rem;
  text-align: center;
  color: #444;
  font-size: 12px;
}
`;

// 运行时生成首页模板，确保域名配置变化时能直接生效。
function buildHomeHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<title>GitHub Proxy</title>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<style>
${COMMON_CSS}

.terminal-window {
  border-color: var(--primary-color);
}

.terminal-header {
  border-bottom-color: var(--secondary-color);
}

.terminal-body {
  text-align: left;
}

.terminal-input-group {
  display: flex;
  gap: 0;
  margin: 1.5rem 0;
}

.terminal-input-group input {
  flex: 1;
  background: #0a0a0a;
  border: 1px solid var(--primary-color);
  border-right: none;
  color: var(--font-color);
  padding: 0.75rem 1rem;
  font-family: var(--global-font-family);
  font-size: 14px;
  outline: none;
}

.terminal-input-group input::placeholder { color: #444; }
.terminal-input-group input:focus { background: #111; }

.terminal-input-group button {
  background: var(--primary-color);
  color: var(--invert-font-color);
  border: 1px solid var(--primary-color);
  padding: 0.75rem 1.5rem;
  font-family: var(--global-font-family);
  font-size: 14px;
  font-weight: bold;
  cursor: pointer;
  transition: all 0.2s;
}

.terminal-input-group button:hover {
  background: var(--secondary-color);
  border-color: var(--secondary-color);
}

.hint {
  margin-top: 1rem;
  color: #666;
  font-size: 13px;
}

.hint code {
  background: #1a1a1a;
  color: var(--primary-color);
  padding: 0.2rem 0.5rem;
  border-radius: 3px;
  border: 1px solid #333;
}

.features {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1rem;
  margin-top: 2rem;
}

.feature {
  border: 1px solid #333;
  padding: 1rem;
  text-align: center;
  transition: border-color 0.2s;
}

.feature:hover { border-color: var(--primary-color); }

.feature-icon {
  font-size: 1.5rem;
  margin-bottom: 0.5rem;
}

.feature-title {
  color: var(--primary-color);
  font-weight: bold;
  font-size: 13px;
  margin-bottom: 0.25rem;
}

.feature-desc {
  color: #666;
  font-size: 11px;
}

.footer {
  margin-top: 2rem;
  text-align: center;
  color: #444;
  font-size: 12px;
}

.footer::before { content: "--- "; color: var(--secondary-color); }
.footer::after { content: " ---"; color: var(--secondary-color); }

.cursor {
  display: inline-block;
  width: 10px;
  height: 18px;
  background: var(--primary-color);
  animation: blink 1s step-end infinite;
  vertical-align: middle;
  margin-left: 2px;
}

@keyframes blink { 50% { opacity: 0; } }

.terminal-title-text {
  font-size: 1.5rem;
  margin: 0 0 0.5rem 0;
}

.terminal-subtitle {
  color: #888;
  margin: 0 0 1.5rem 0;
  font-size: 14px;
}

.status-line {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 1.5rem;
  font-size: 13px;
}

.status-indicator {
  width: 8px;
  height: 8px;
  background: var(--primary-color);
  border-radius: 50%;
  animation: pulse 2s infinite;
}

@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }

@media (max-width: 600px) {
  .container { padding: 1rem; }
  .features { grid-template-columns: 1fr; }
  .terminal-input-group { flex-direction: column; }
  .terminal-input-group input {
    border-right: 1px solid var(--primary-color);
    border-bottom: none;
  }
  .terminal-input-group button { border-top: none; }
}
</style>
</head>
<body>
<div class="container">
  <div class="terminal-window">
    <div class="terminal-header">
      <span class="terminal-btn close"></span>
      <span class="terminal-btn minimize"></span>
      <span class="terminal-btn maximize"></span>
      <span class="terminal-title">github-proxy — bash — 80x24</span>
    </div>
    <div class="terminal-body">
      <div class="prompt-line">
        <span class="prompt"><span class="prompt-user">user</span>@<span class="prompt-host">proxy</span>:<span class="prompt-path">~</span>$</span>
        <span>./github-proxy --status</span>
      </div>
      
      <div class="status-line">
        <span class="status-indicator"></span>
        <span>GitHub Proxy Service [RUNNING]</span>
      </div>
      
      <h1 class="terminal-title-text">加速访问 GitHub</h1>
      <p class="terminal-subtitle">输入 GitHub 仓库地址或链接，即刻通过代理快速访问。</p>
      
      <div class="prompt-line">
        <span class="prompt"><span class="prompt-user">user</span>@<span class="prompt-host">proxy</span>:<span class="prompt-path">~</span>$</span>
        <span>./proxy --input</span>
      </div>
      
      <form class="terminal-input-group" id="f" onsubmit="return go()">
        <input type="text" id="u" placeholder="owner/repo、关键词 或 https://github.com/..." autocomplete="off" spellcheck="false" autofocus/>
        <button type="submit">EXECUTE</button>
      </form>
      
      <p class="hint">
        <span class="prompt">$</span> <span style="color:#666"># 例如</span> <code>torvalds/linux</code><span style="color:#666">、</span><code>react hooks</code> <span style="color:#666">或</span> <code>https://github.com/vuejs/core</code>
      </p>
      
      <div class="prompt-line" style="margin-top: 2rem;">
        <span class="prompt"><span class="prompt-user">user</span>@<span class="prompt-host">proxy</span>:<span class="prompt-path">~</span>$</span>
        <span>cat features.txt</span>
      </div>
      
      <div class="features">
        <div class="feature">
          <div class="feature-icon">⚡</div>
          <div class="feature-title">极速代理</div>
          <div class="feature-desc">全球 CDN 加速</div>
        </div>
        <div class="feature">
          <div class="feature-icon">🔒</div>
          <div class="feature-title">安全访问</div>
          <div class="feature-desc">敏感路径自动过滤</div>
        </div>
        <div class="feature">
          <div class="feature-icon">📦</div>
          <div class="feature-title">全量支持</div>
          <div class="feature-desc">仓库 / Raw / Release</div>
        </div>
      </div>
      
      <div class="footer">
        Powered by Cloudflare Workers
      </div>
      
      <div class="prompt-line" style="margin-top: 1.5rem;">
        <span class="prompt"><span class="prompt-user">user</span>@<span class="prompt-host">proxy</span>:<span class="prompt-path">~</span>$</span>
        <span class="cursor"></span>
      </div>
    </div>
  </div>
</div>

<script>
function go() {
  const inputEl = document.getElementById('u');
  if (!inputEl) return false;

  let v = inputEl.value.trim();
  if (!v) return false;

  const ghMatch = v.match(/^(?:https?:\\/\\/(?:www\\.)?)?github\\.com\\/(.+)/i);
  if (ghMatch) {
    v = ghMatch[1];
  } else if (/^https?:\\/\\//i.test(v)) {
    location.href = '/not_found';
    return false;
  }

  v = v.replace(/^\\/+/, '');

  // owner/repo 或 owner 格式 → 直接跳转
  const isPathLike = /^[A-Za-z0-9_.-]+(?:\\/[A-Za-z0-9_.-]+)*\\/?$/.test(v);

  if (isPathLike) {
    location.href = '/' + v;
  } else {
    // 其他输入视为搜索关键词
    location.href = '/search?q=' + encodeURIComponent(v);
  }

  return false;
}
</script>
</body>
</html>`;
}

function buildNotFoundHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<title>404 - 页面不存在</title>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<style>
${COMMON_CSS}

.terminal-window {
  border-color: var(--error-color);
}

.terminal-header {
  border-bottom-color: var(--error-color);
}

.cursor {
  background: var(--error-color);
}

.footer::before { content: "--- "; color: var(--error-color); }
.footer::after { content: " ---"; color: var(--error-color); }

@media (max-width: 600px) {
  .container { padding: 1rem; }
  .ascii-art { font-size: 8px; }
}
</style>
</head>
<body>
<div class="container">
  <div class="terminal-window">
    <div class="terminal-header">
      <span class="terminal-btn close"></span>
      <span class="terminal-btn minimize"></span>
      <span class="terminal-btn maximize"></span>
      <span class="terminal-title">github-proxy — bash — 80x24</span>
    </div>
    <div class="terminal-body">
      <div class="prompt-line">
        <span class="prompt"><span class="prompt-user">user</span>@<span class="prompt-host">proxy</span>:<span class="prompt-path">~</span>$</span>
        <span>curl <span id="current-path"></span></span>
      </div>
      
      <div class="ascii-art">
   _  _     ___   _  _
  | || |   / _ \\ | || |
  | || |_ | | | || || |_
  |__   _|| | | ||__   _|
     | |  | |_| |   | |
     |_|   \\___/    |_|
      </div>
      
      <div class="error-code">404</div>
      
      <h1 class="error-title">页面不存在</h1>
      <p class="error-subtitle">你访问的资源不存在，或者该路径已被安全策略屏蔽。</p>
      
      <div class="error-details">
        <div class="line">
          <span class="line-num">1</span>
          <span class="line-content">$ curl -I <span id="error-path"></span></span>
        </div>
        <div class="line">
          <span class="line-num">2</span>
          <span class="line-content">HTTP/1.1 404 Not Found</span>
        </div>
        <div class="line">
          <span class="line-num">3</span>
          <span class="line-content error">Error: Resource not found or access denied</span>
        </div>
        <div class="line">
          <span class="line-num">4</span>
          <span class="line-content">Connection: close</span>
        </div>
      </div>
      
      <a href="https://${ENTRY_DOMAIN}/" class="back-btn">← 返回首页</a>
      
      <div class="footer">
        Error Code: 404 | Not Found
      </div>
      
      <div class="prompt-line" style="margin-top: 1.5rem;">
        <span class="prompt"><span class="prompt-user">user</span>@<span class="prompt-host">proxy</span>:<span class="prompt-path">~</span>$</span>
        <span class="cursor"></span>
      </div>
    </div>
  </div>
</div>

<script>
document.getElementById('current-path').textContent = window.location.pathname;
document.getElementById('error-path').textContent = window.location.href;
</script>
</body>
</html>`;
}

// ===================== 主处理 =====================

// 统一入口，根据请求域名分发到入口页或代理逻辑。
export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, ctx);
  },
};

async function handleRequest(request, ctx) {
  const url = new URL(request.url);
  const origin = request.headers.get('Origin') || '';
  const effectiveHost = stripPort(request.headers.get('Host') || url.host);

  if (url.protocol === 'http:') {
    url.protocol = 'https:';
    return Response.redirect(url.toString(), 301);
  }

  if (effectiveHost === ENTRY_DOMAIN) {
    return handleEntryRequest(url, origin);
  }

  return handleProxyRequest(request, url, origin, effectiveHost, ctx);
}

function handleEntryRequest(url, origin) {
  if (url.pathname === '/') {
    return htmlResponse(buildHomeHtml(), 200, origin);
  }
  if (['/favicon.ico', '/robots.txt'].includes(url.pathname)) {
    return new Response(null, { status: 404 });
  }
  const redir = new URL(url);
  redir.host = getProxyHostByOrigin('github.com');
  return Response.redirect(redir.toString(), 302);
}

async function handleProxyRequest(request, url, origin, effectiveHost, ctx) {
  const NOT_FOUND = () => htmlResponse(buildNotFoundHtml(), 404, origin);

  const hostPrefix = getProxyPrefix(effectiveHost);
  if (!hostPrefix) return NOT_FOUND();

  const currentOrigin = getOriginByPrefix(hostPrefix);
  if (!currentOrigin) return NOT_FOUND();

  const geoRedirect = tryGeoRedirect(request, currentOrigin, url);
  if (geoRedirect) return geoRedirect;

  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: applyCorsHeaders(new Headers(), origin),
    });
  }

  // 只读代理：仅允许 GET / HEAD，拒绝所有写操作。
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return new Response('Method Not Allowed', {
      status: 405,
      headers: { ...Object.fromEntries(applyCorsHeaders(new Headers(), origin)), 'Allow': 'GET, HEAD, OPTIONS' },
    });
  }

  const originalPath = url.pathname;
  const originalSearch = url.search || '';
  const extracted = extractTargetFromPath(originalPath);
  const canonicalPath = extracted?.pathname ?? originalPath;
  const mergedSearch = mergeSearch(originalSearch, extracted?.search || '');

  if (shouldRedirectGithubProxyRootToEntry(request, canonicalPath, currentOrigin)) {
    return Response.redirect(`https://${ENTRY_DOMAIN}/`, 302);
  }

  // 对路径做解码和规范化后再进行敏感路径检测。
  const decodedPath = safeDecodeURI(canonicalPath);
  if (
    githubRedirectPatterns.some(re => re.test(canonicalPath)) ||
    githubRedirectPatterns.some(re => re.test(decodedPath))
  ) {
    return NOT_FOUND();
  }
  if (ENABLE_STRICT_DEFENSE && (
    extraDefensePatterns.some(re => re.test(canonicalPath)) ||
    extraDefensePatterns.some(re => re.test(decodedPath))
  )) {
    return NOT_FOUND();
  }

  // 拦截查询参数中的敏感跳转目标。
  if (hasSensitiveQueryParam(mergedSearch)) {
    return NOT_FOUND();
  }

  // 跨域重定向
  if (extracted) {
    const desiredPrefix = getProxyHostByOrigin(extracted.target_host);
    if (desiredPrefix) {
      const desiredHost = stripPort(desiredPrefix);
      const redirectStatus = (request.method === 'GET' || request.method === 'HEAD') ? 301 : 307;

      if (desiredHost !== effectiveHost) {
        const redir = new URL(url);
        redir.protocol = 'https:';
        redir.host = desiredHost;
        redir.pathname = canonicalPath;
        redir.search = mergedSearch;
        return Response.redirect(redir.toString(), redirectStatus);
      }

      if (originalPath !== canonicalPath || extracted.search) {
        const redir = new URL(url);
        redir.pathname = canonicalPath;
        redir.search = mergedSearch;
        return Response.redirect(redir.toString(), redirectStatus);
      }
    }
  }

  const pathname = fixCommitInfoPath(canonicalPath);
  const upstream = new URL(url);
  upstream.protocol = 'https:';
  upstream.host = currentOrigin;
  upstream.pathname = pathname;

  // 转发前清理敏感查询参数。
  upstream.search = sanitizeSearchParams(mergedSearch);

  // 构建上游请求头
  const headers = new Headers(request.headers);
  headers.set('Host', currentOrigin);
  headers.delete('accept-encoding');

  if (headers.has('Origin')) headers.set('Origin', `https://${currentOrigin}`);

  const referer = headers.get('Referer');
  if (referer) {
    try {
      const refUrl = new URL(referer);
      const p = getProxyPrefix(refUrl.host);
      if (p) { const o = getOriginByPrefix(p); if (o) refUrl.host = o; }
      headers.set('Referer', refUrl.href);
    } catch (_) {
      headers.set('Referer', upstream.href);
    }
  } else {
    headers.set('Referer', upstream.href);
  }

  for (const h of SENSITIVE_REQ_HEADERS) {
    headers.delete(h);
  }


  // 仅转发匿名访问所需的 Cookie。
  const safeCookie = sanitizeCookies(headers.get('cookie') || '');
  if (safeCookie) {
    headers.set('cookie', safeCookie);
  } else {
    headers.delete('cookie');
  }

  // ── Cache API 缓存层 ──
  const isCacheable = ENABLE_CACHE && (request.method === 'GET' || request.method === 'HEAD');
  const cache = isCacheable ? caches.default : null;
  // 用上游 URL 做缓存键，确保不同代理子域共享同一缓存条目。
  const cacheKey = isCacheable ? new Request(upstream.href, { method: 'GET' }) : null;

  if (cache && cacheKey) {
    const cached = await cache.match(cacheKey);
    if (cached) {
      // 命中缓存：改写 CORS 头后直接返回。
      const cachedHeaders = new Headers(cached.headers);
      applyCorsHeaders(cachedHeaders, origin);
      // HEAD 请求不应返回 body
      const cachedBody = request.method === 'HEAD' ? null : cached.body;
      return new Response(cachedBody, { status: cached.status, headers: cachedHeaders });
    }
  }

  // 为上游请求设置超时控制。
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);

  try {
    const resp = await fetch(upstream.href, {
      method: request.method,
      headers,
      redirect: 'manual',
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    // 改写上游重定向
    if ([301, 302, 303, 307, 308].includes(resp.status)) {
      const loc = resp.headers.get('Location');
      if (loc) {
        let newLoc = loc;
        try {
          const locUrl = new URL(loc, upstream.href);
          const locHost = stripPort(locUrl.host);

          const mappedOrigin = findMappingForHost(locHost);
          if (mappedOrigin) {
            locUrl.host = getProxyHostByOrigin(mappedOrigin);
            locUrl.protocol = 'https:';
            newLoc = locUrl.toString();
          }
          // 记录未纳入白名单的上游重定向目标，便于补充映射。
          else {
            console.warn('[Redirect] Unmapped upstream redirect target:', locHost, '→', loc);
          }
        } catch (_) {}
        const redirectHeaders = new Headers(resp.headers);
        redirectHeaders.set('Location', newLoc);
        applyCorsHeaders(redirectHeaders, origin);
        return new Response(resp.body, {
          status: resp.status,
          headers: redirectHeaders,
        });
      }
    }

    if (resp.status === 404) return NOT_FOUND();

    const ct = resp.headers.get('content-type') || '';
    const upstreamCC = resp.headers.get('cache-control') || '';

    const respHeaders = new Headers(resp.headers);
    applyCorsHeaders(respHeaders, origin);

    respHeaders.set('cache-control', computeCacheControl(ct, upstreamCC));

    for (const h of STRIP_RESP_HEADERS) {
      respHeaders.delete(h);
    }

    // 直接消费上游响应体并按需改写。
    const body = await modifyResponse(resp);

    const finalResponse = new Response(body, { status: resp.status, headers: respHeaders });

    // 仅缓存 200 且上游未明确禁止缓存的 GET 响应。
    if (cache && cacheKey && resp.status === 200) {
      const ccLower = (respHeaders.get('cache-control') || '').toLowerCase();
      if (!ccLower.includes('no-store') && !ccLower.includes('private')) {
        const toCache = finalResponse.clone();
        // 如果上游未提供明确的 max-age，用默认 TTL 确保缓存会过期。
        if (!ccLower.includes('max-age') && !ccLower.includes('s-maxage')) {
          const cacheHeaders = new Headers(toCache.headers);
          cacheHeaders.set('cache-control', `public, s-maxage=${CACHE_TTL}`);
          const cacheResp = new Response(toCache.body, { status: toCache.status, headers: cacheHeaders });
          ctx.waitUntil(cache.put(cacheKey, cacheResp));
        } else {
          ctx.waitUntil(cache.put(cacheKey, toCache));
        }
      }
    }

    return finalResponse;
  } catch (err) {
    clearTimeout(timeoutId);

    // 超时和其他上游错误分别返回不同状态码。
    if (err.name === 'AbortError') {
      console.error('[Proxy Timeout]', upstream.href);
      return new Response('Proxy Error: Upstream request timed out.', {
        status: 504,
        headers: applyCorsHeaders(new Headers({ 'content-type': 'text/plain' }), origin),
      });
    }

    console.error('[Proxy Error]', upstream.href, err.message, err.stack);
    return new Response('Proxy Error: An internal error occurred while fetching the upstream resource.', {
      status: 502,
      headers: applyCorsHeaders(new Headers({ 'content-type': 'text/plain' }), origin),
    });
  }
}
