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
  'set-cookie',
  'x-frame-options',
  'content-length', // 内容经过改写，原始 content-length 不再准确
];

const MAX_REWRITE_SIZE = 5 * 1024 * 1024; // 5MB
const UPSTREAM_TIMEOUT_MS = 15000;
const GITHUB_TOKEN_ENV = 'GITHUB_TOKEN';
const GITHUB_TOKEN_METHODS = new Set(['GET', 'HEAD']);

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
  'release-assets.githubusercontent.com',
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
    'access-control-allow-methods': 'GET, HEAD, POST, OPTIONS',
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

function stripUnsafeResponseHeaders(headers) {
  for (const h of STRIP_RESP_HEADERS) {
    headers.delete(h);
  }
  return headers;
}

function wantsHtmlErrorPage(request) {
  if (request.method === 'HEAD') return false;
  const accept = (request.headers.get('accept') || '').toLowerCase();
  return accept.includes('text/html');
}

function htmlResponse(html, status, origin) {
  const headers = new Headers({ 'content-type': 'text/html; charset=utf-8' });
  applyCorsHeaders(headers, origin);
  return new Response(html, {
    status,
    headers,
  });
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escapeAttr(value) {
  return escapeHtml(value);
}

function formatCompactNumber(value) {
  const n = Number(value || 0);
  if (!Number.isFinite(n)) return '0';
  if (n >= 1000000) return `${(n / 1000000).toFixed(n >= 10000000 ? 0 : 1).replace(/\.0$/, '')}m`;
  if (n >= 1000) return `${(n / 1000).toFixed(n >= 10000 ? 0 : 1).replace(/\.0$/, '')}k`;
  return String(n);
}

function formatDate(value) {
  if (!value) return '';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleDateString('en', { month: 'short', day: 'numeric', year: 'numeric' });
}

function buildQueryString(params) {
  const out = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      out.set(key, String(value));
    }
  }
  const s = out.toString();
  return s ? `?${s}` : '';
}

function rewriteOriginalUrlToProxy(value) {
  if (!value) return '';
  try {
    const u = new URL(value);
    const proxyHost = getProxyHostByOrigin(u.hostname);
    if (proxyHost) {
      u.protocol = 'https:';
      u.host = proxyHost;
    }
    return u.toString();
  } catch (_) {
    return value;
  }
}

function normalizeSearchType(type) {
  const value = String(type || 'repositories').toLowerCase();
  return SEARCH_TYPE_ALIASES[value] || value;
}

function buildIssueSearchQuery(q, type) {
  const base = String(q || '').replace(/\bis:(?:issue|pr)\b/gi, '').replace(/\s+/g, ' ').trim();
  const qualifier = type === 'pullrequests' ? 'is:pr' : 'is:issue';
  return `${base} ${qualifier}`.trim();
}

// Search type behavior lives in one table so adding a new tab is a data change,
// not a chain of route/render conditionals.
const SEARCH_TYPE_ALIASES = {
  pr: 'pullrequests',
  prs: 'pullrequests',
  pull_request: 'pullrequests',
  pull_requests: 'pullrequests',
  'pull-request': 'pullrequests',
  'pull-requests': 'pullrequests',
};

const SEARCH_TYPES = {
  code: {
    tab: 'Code',
    label: 'code',
    plural: 'code',
    endpoint: 'https://api.github.com/search/code',
    scope: 'Code search uses GitHub REST Code Search. It may require GITHUB_TOKEN.',
    sorts: [
      ['Best match', ''],
      ['Recently indexed', 'indexed'],
    ],
    buildQuery: q => q,
    renderResult: buildCodeResultHtml,
  },
  repositories: {
    tab: 'Repositories',
    label: 'repository',
    plural: 'repositories',
    endpoint: 'https://api.github.com/search/repositories',
    scope: '',
    sorts: [
      ['Best match', ''],
      ['Most stars', 'stars'],
      ['Most forks', 'forks'],
      ['Recently updated', 'updated'],
    ],
    buildQuery: q => q,
    renderResult: buildRepositoryResultHtml,
    renderFacet: buildRepositorySearchFacetHtml,
  },
  issues: {
    tab: 'Issues',
    label: 'issue',
    plural: 'issues',
    endpoint: 'https://api.github.com/search/issues',
    scope: 'Only issues are included.',
    sorts: [
      ['Best match', ''],
      ['Most commented', 'comments'],
      ['Newest', 'created'],
      ['Recently updated', 'updated'],
    ],
    buildQuery: q => buildIssueSearchQuery(q, 'issues'),
    renderResult: buildIssueResultHtml,
  },
  pullrequests: {
    tab: 'Pull requests',
    label: 'pull request',
    plural: 'pull requests',
    endpoint: 'https://api.github.com/search/issues',
    scope: 'Only pull requests are included.',
    sorts: [
      ['Best match', ''],
      ['Most commented', 'comments'],
      ['Newest', 'created'],
      ['Recently updated', 'updated'],
    ],
    buildQuery: q => buildIssueSearchQuery(q, 'pullrequests'),
    renderResult: buildIssueResultHtml,
  },
  users: {
    tab: 'Users',
    label: 'user',
    plural: 'users',
    endpoint: 'https://api.github.com/search/users',
    scope: 'Users and organizations returned by GitHub user search.',
    sorts: [
      ['Best match', ''],
      ['Most followers', 'followers'],
      ['Most repositories', 'repositories'],
      ['Recently joined', 'joined'],
    ],
    buildQuery: q => q,
    renderResult: buildUserResultHtml,
  },
};

function getSearchConfig(type) {
  return SEARCH_TYPES[normalizeSearchType(type)] || null;
}

function getSearchSortValues(config) {
  return new Set(config.sorts.map(([, value]) => value).filter(Boolean));
}

function parseSearchRequest(url) {
  const type = normalizeSearchType(url.searchParams.get('type') || 'repositories');
  return {
    q: (url.searchParams.get('q') || '').trim().slice(0, 256),
    type,
    config: getSearchConfig(type),
    page: Math.max(1, Math.min(Number.parseInt(url.searchParams.get('p') || url.searchParams.get('page') || '1', 10) || 1, 100)),
    sort: (url.searchParams.get('sort') || '').toLowerCase(),
    order: (url.searchParams.get('order') || '').toLowerCase() === 'asc' ? 'asc' : 'desc',
  };
}

function buildSearchApiUrl({ q, config, page, sort, order }) {
  const apiUrl = new URL(config.endpoint);
  apiUrl.searchParams.set('q', config.buildQuery(q));
  apiUrl.searchParams.set('per_page', '10');
  apiUrl.searchParams.set('page', String(page));
  if (getSearchSortValues(config).has(sort)) {
    apiUrl.searchParams.set('sort', sort);
    apiUrl.searchParams.set('order', order);
  }
  return apiUrl;
}

function buildSearchApiHeaders(env) {
  const headers = new Headers({
    'accept': 'application/vnd.github+json',
    'user-agent': 'gh-proxy-search-ui',
    'x-github-api-version': '2022-11-28',
  });
  const token = getGitHubToken(env);
  if (token) headers.set('Authorization', `Bearer ${token}`);
  return headers;
}

function readSearchRateLimit(headers) {
  return {
    limit: headers.get('x-ratelimit-limit') || '',
    remaining: headers.get('x-ratelimit-remaining') || '',
    used: headers.get('x-ratelimit-used') || '',
    reset: headers.get('x-ratelimit-reset') || '',
    resource: headers.get('x-ratelimit-resource') || '',
  };
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

function isGitUploadPackPath(pathname) {
  return /^\/[^/]+\/[^/]+\.git\/git-upload-pack$/i.test(pathname);
}

function isAllowedProxyMethod(request, currentOrigin, pathname) {
  if (request.method === 'GET' || request.method === 'HEAD') return true;
  if (request.method !== 'POST') return false;
  if (currentOrigin !== 'github.com') return false;

  return isGitUploadPackPath(pathname);
}

function shouldBlockGithubWebPath(currentOrigin, pathname) {
  if (currentOrigin !== 'github.com') return false;
  return githubRedirectPatterns.some(re => re.test(pathname));
}

function shouldBlockStrictDefensePath(currentOrigin, pathname) {
  if (currentOrigin === 'api.github.com') return false;
  return extraDefensePatterns.some(re => re.test(pathname));
}

function isGitHubTokenOrigin(origin) {
  const host = stripPort(origin);
  return (
    host === 'github.com' ||
    host.endsWith('.github.com') ||
    host === 'githubusercontent.com' ||
    host.endsWith('.githubusercontent.com') ||
    host === 'github.githubassets.com' ||
    host === 'assets-cdn.github.com'
  );
}

function getGitHubToken(env) {
  const token = env?.[GITHUB_TOKEN_ENV];
  return typeof token === 'string' ? token.trim() : '';
}

function isSensitiveGitHubApiPath(pathname) {
  const decodedPath = safeDecodeURI(pathname);

  return [
    // Token / identity context.
    /^\/(?:user|notifications|authorizations|applications|installation|installations|app)(?:\/|$)/i,

    // Repository administration or security metadata.
    /^\/repos\/[^/]+\/[^/]+\/(?:actions\/secrets|actions\/runners|collaborators|deployments|environments|hooks|keys|rules|rulesets|secret-scanning|code-scanning|dependabot|vulnerability-alerts|automated-security-fixes|traffic)(?:\/|$)/i,

    // Organization administration metadata.
    /^\/orgs\/[^/]+\/(?:credential-authorizations|personal-access-tokens|outside-collaborators|hooks|installations|actions\/secrets|actions\/runners|security-managers)(?:\/|$)/i,

    // Enterprise and billing/admin surfaces should never use a shared proxy token.
    /^\/(?:enterprises|organizations|billing|marketplace_listing)(?:\/|$)/i,
  ].some(re => re.test(decodedPath));
}

function isSensitiveGitHubTokenPath(currentOrigin, pathname) {
  if (currentOrigin === 'api.github.com') return isSensitiveGitHubApiPath(pathname);
  if (currentOrigin === 'github.com') return shouldBlockGithubWebPath(currentOrigin, pathname);
  return false;
}

function isHtmlNavigationRequest(request) {
  const accept = (request.headers.get('accept') || '').toLowerCase();
  return accept.includes('text/html');
}

function shouldAttachGitHubToken(request, currentOrigin, pathname) {
  if (!isGitHubTokenOrigin(currentOrigin)) return false;
  if (!GITHUB_TOKEN_METHODS.has(request.method)) return false;
  if (isSensitiveGitHubTokenPath(currentOrigin, pathname)) return false;

  // GitHub 主站 HTML 不使用服务端 token，避免返回 token 持有者上下文相关页面。
  if (currentOrigin === 'github.com' && isHtmlNavigationRequest(request)) return false;

  return true;
}

function attachGitHubToken(headers, env, request, currentOrigin, pathname) {
  if (!shouldAttachGitHubToken(request, currentOrigin, pathname)) return;

  const token = getGitHubToken(env);
  if (!token) return;

  headers.set('Authorization', `Bearer ${token}`);
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
  const sensitiveParams = new Set([...SENSITIVE_URL_PARAMS, ...SENSITIVE_QUERY_PARAMS]);

  for (const key of Array.from(params.keys())) {
    if (sensitiveParams.has(key.toLowerCase())) {
      params.delete(key);
    }
  }

  const result = params.toString();
  return result ? '?' + result : '';
}

function hasSensitiveQueryParam(searchStr) {
  if (!searchStr) return false;

  const params = new URLSearchParams(searchStr.replace(/^\?/, ''));
  const sensitiveParams = new Set(SENSITIVE_QUERY_PARAMS);

  for (const [key, value] of params) {
    if (
      sensitiveParams.has(key.toLowerCase()) &&
      value &&
      githubRedirectPatterns.some(re => re.test(value))
    ) {
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
var DOMAIN_MAP = ${JSON.stringify(domain_mappings)};
function go() {
  const inputEl = document.getElementById('u');
  if (!inputEl) return false;

  let v = inputEl.value.trim();
  if (!v) return false;

  const ghMatch = v.match(/^(?:https?:\\/\\/(?:www\\.)?)?github\\.com\\/(.+)/i);
  if (ghMatch) {
    v = ghMatch[1];
  } else if (/^https?:\\/\\//i.test(v)) {
    try {
      const u = new URL(v);
      const h = u.hostname.toLowerCase();
      const proxy = DOMAIN_MAP[h] || DOMAIN_MAP[h.replace(/^www\\./, '')];
      if (proxy) {
        location.href = 'https://' + proxy + u.pathname + u.search;
        return false;
      }
    } catch (_) {}
  }

  v = v.replace(/^\\/+/, '');

  // owner/repo 或 owner 格式 → 直接跳转
  const isPathLike = /^[A-Za-z0-9_.-]+(?:\\/[A-Za-z0-9_.-]+)*\\/?$/.test(v);

  if (isPathLike) {
    location.href = '/' + v;
  } else {
    // 其他输入视为搜索关键词
    location.href = '/search?q=' + encodeURIComponent(v) + '&type=repositories';
  }

  return false;
}
</script>
</body>
</html>`;
}

async function handleSearchRequest(url, origin, env) {
  const params = parseSearchRequest(url);

  if (!params.q) {
    return htmlResponse(buildSearchHtml({ ...params, result: null, error: null, rate: null }), 200, origin);
  }

  if (!params.config) {
    const unsupportedType = params.type;
    return htmlResponse(buildSearchHtml({
      ...params,
      type: 'repositories',
      config: SEARCH_TYPES.repositories,
      result: null,
      rate: null,
      error: `API-driven search currently supports code, repositories, issues, pull requests, and users. "${unsupportedType}" can be added with a dedicated renderer.`,
    }), 400, origin);
  }

  const apiUrl = buildSearchApiUrl(params);
  const headers = buildSearchApiHeaders(env);

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);

  try {
    const resp = await fetch(apiUrl.toString(), {
      method: 'GET',
      headers,
      redirect: 'manual',
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    const rate = readSearchRateLimit(resp.headers);

    let data = null;
    let error = null;
    try {
      data = await resp.json();
    } catch (_) {
      error = `GitHub returned ${resp.status}.`;
    }

    if (!resp.ok) {
      error = data?.message || error || `GitHub returned ${resp.status}.`;
    }

    return htmlResponse(buildSearchHtml({ ...params, result: data, error, rate }), resp.ok ? 200 : resp.status, origin);
  } catch (err) {
    clearTimeout(timeoutId);
    const error = err.name === 'AbortError' ? 'GitHub Search API timed out.' : 'GitHub Search API request failed.';
    return htmlResponse(buildSearchHtml({ ...params, result: null, error, rate: null }), err.name === 'AbortError' ? 504 : 502, origin);
  }
}

function buildSearchHtml({ q, type, config, page, sort, order, result, error, rate }) {
  const searchConfig = config || getSearchConfig(type) || SEARCH_TYPES.repositories;
  const items = Array.isArray(result?.items) ? result.items : [];
  const total = Number(result?.total_count || 0);
  const pageCount = Math.max(1, Math.min(Math.ceil(total / 10), 100));
  const typeLabel = searchConfig.label;
  const pluralTypeLabel = searchConfig.plural;
  const title = q ? `${typeLabel} search results - ${q}` : `${typeLabel} search`;

  const tabLink = (label, tabType) => {
    const active = type === tabType;
    const href = `/search${buildQueryString({ q, type: tabType })}`;
    return `<a class="search-tab ${active ? 'active' : ''}" href="${escapeAttr(href)}">${escapeHtml(label)}</a>`;
  };
  const tabsHtml = Object.entries(SEARCH_TYPES)
    .map(([tabType, tabConfig]) => tabLink(tabConfig.tab, tabType))
    .join('');

  const sortLink = (label, value) => {
    const active = sort === value || (!sort && value === '');
    const href = `/search${buildQueryString({ q, type, sort: value, order: value ? 'desc' : '', p: 1 })}`;
    return `<a class="sort-link ${active ? 'active' : ''}" href="${escapeAttr(href)}">${escapeHtml(label)}</a>`;
  };

  const resultHtml = items.map(item => searchConfig.renderResult(item)).join('') || `
    <div class="empty-state">
      <h2>${q ? `No ${escapeHtml(pluralTypeLabel)} found` : `Search GitHub ${escapeHtml(pluralTypeLabel)}`}</h2>
      <p>${q ? 'Try a different query or remove some filters.' : 'Enter a keyword, owner/repo, topic, or qualifier.'}</p>
    </div>`;

  const sortHtml = searchConfig.sorts.map(([label, value]) => sortLink(label, value)).join('');
  const paginationHtml = buildSearchPagination(q, type, page, pageCount, sort, order);
  const rateHtml = rate ? `<span>Search API: ${escapeHtml(rate.remaining)}/${escapeHtml(rate.limit)} remaining, used ${escapeHtml(rate.used)}</span>` : '';
  const errorHtml = error ? `<div class="search-error">${escapeHtml(error)}</div>` : '';
  const facetHtml = searchConfig.renderFacet
    ? searchConfig.renderFacet(q, items)
    : buildSearchScopeFacetHtml(searchConfig.scope);

  return `<!DOCTYPE html>
<html lang="en" data-color-mode="auto">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${escapeHtml(title)}</title>
<style>
:root {
  color-scheme: light dark;
  --bg: #ffffff;
  --fg: #1f2328;
  --muted: #59636e;
  --border: #d1d9e0;
  --subtle: #f6f8fa;
  --accent: #0969da;
  --success: #1a7f37;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117;
    --fg: #e6edf3;
    --muted: #8b949e;
    --border: #30363d;
    --subtle: #161b22;
    --accent: #58a6ff;
    --success: #3fb950;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.topbar {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 16px 24px;
  border-bottom: 1px solid var(--border);
  background: var(--subtle);
}
.mark {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  background: var(--fg);
  color: var(--bg);
  display: grid;
  place-items: center;
  font-weight: 700;
}
.search-form {
  flex: 1;
  display: flex;
  max-width: 780px;
}
.search-form input {
  width: 100%;
  height: 36px;
  padding: 0 12px;
  border: 1px solid var(--border);
  border-radius: 6px 0 0 6px;
  background: var(--bg);
  color: var(--fg);
  font: inherit;
}
.search-form button {
  height: 36px;
  padding: 0 14px;
  border: 1px solid var(--border);
  border-left: 0;
  border-radius: 0 6px 6px 0;
  background: var(--subtle);
  color: var(--fg);
  font: inherit;
  cursor: pointer;
}
.layout {
  display: grid;
  grid-template-columns: 280px minmax(0, 1fr);
  min-height: calc(100vh - 69px);
}
.sidebar {
  border-right: 1px solid var(--border);
  padding: 24px;
}
.content {
  padding: 24px 32px 48px;
  max-width: 1080px;
}
.filter-title {
  margin: 0 0 12px;
  font-size: 16px;
}
.search-tab, .facet-link, .sort-link {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 10px;
  border-radius: 6px;
  color: var(--fg);
}
.search-tab.active, .sort-link.active {
  background: var(--subtle);
  font-weight: 600;
}
.facet-group {
  margin-top: 24px;
  padding-top: 20px;
  border-top: 1px solid var(--border);
}
.facet-heading {
  margin: 0 0 8px;
  font-size: 12px;
  color: var(--muted);
  text-transform: uppercase;
}
.language-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: #89e051;
  flex: 0 0 auto;
}
.subhead {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 8px;
}
.count {
  font-size: 16px;
  font-weight: 600;
}
.rate {
  color: var(--muted);
  font-size: 12px;
}
.sorts {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  margin: 8px 0 16px;
}
.sort-link {
  border: 1px solid var(--border);
  padding: 5px 10px;
  font-size: 12px;
}
.result {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 16px;
  padding: 20px 0;
  border-top: 1px solid var(--border);
}
.result-title {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 8px;
  font-size: 18px;
  font-weight: 600;
}
.avatar {
  width: 20px;
  height: 20px;
  border-radius: 50%;
}
.description {
  max-width: 760px;
  margin: 0 0 10px;
  color: var(--muted);
}
.meta, .topics {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  color: var(--muted);
  font-size: 12px;
}
.topic {
  padding: 2px 8px;
  border-radius: 999px;
  background: color-mix(in srgb, var(--accent) 12%, transparent);
  color: var(--accent);
  font-weight: 500;
}
.star-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 5px 12px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--subtle);
  color: var(--fg);
  font-size: 12px;
}
.state-badge {
  display: inline-flex;
  align-items: center;
  padding: 1px 7px;
  border-radius: 999px;
  background: var(--success);
  color: #fff;
  font-size: 12px;
  font-weight: 600;
}
.state-badge.closed {
  background: #8250df;
}
.repo-link {
  color: var(--muted);
  font-size: 12px;
}
.empty-state, .search-error {
  border-top: 1px solid var(--border);
  padding: 32px 0;
}
.search-error {
  color: #b42318;
  font-weight: 600;
}
.pagination {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 24px;
}
.pagination a, .pagination span {
  padding: 6px 10px;
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--fg);
}
.pagination .active {
  background: var(--accent);
  border-color: var(--accent);
  color: #fff;
}
.muted { color: var(--muted); }
.small { font-size: 12px; }
@media (max-width: 800px) {
  .topbar { align-items: stretch; flex-direction: column; padding: 12px; }
  .layout { grid-template-columns: 1fr; }
  .sidebar { border-right: 0; border-bottom: 1px solid var(--border); padding: 16px; }
  .content { padding: 16px; }
  .subhead, .result { display: block; }
  .star-btn { margin-top: 12px; }
}
</style>
</head>
<body>
<header class="topbar">
  <a class="mark" href="https://${ENTRY_DOMAIN}/" aria-label="GitHub Proxy">GH</a>
  <form class="search-form" action="/search" method="get">
    <input name="q" value="${escapeAttr(q)}" placeholder="Search ${escapeAttr(pluralTypeLabel)}" autocomplete="off"/>
    <input type="hidden" name="type" value="${escapeAttr(type)}"/>
    <button type="submit">Search</button>
  </form>
</header>
<div class="layout">
  <aside class="sidebar">
    <h2 class="filter-title">Filter by</h2>
    ${tabsHtml}
    ${facetHtml}
  </aside>
  <main class="content">
    <div class="subhead">
      <div class="count">${q ? `${formatCompactNumber(total)} ${escapeHtml(typeLabel)} results` : `${escapeHtml(typeLabel)} search`}</div>
      <div class="rate">${rateHtml}</div>
    </div>
    <div class="sorts">
      ${sortHtml}
    </div>
    ${errorHtml}
    ${resultHtml}
    ${paginationHtml}
  </main>
</div>
</body>
</html>`;
}

function buildRepositoryResultHtml(item) {
  const fullName = item.full_name || `${item.owner?.login || ''}/${item.name || ''}`;
  const href = `/${fullName}`;
  const avatar = rewriteOriginalUrlToProxy(item.owner?.avatar_url || '');
  const topics = Array.isArray(item.topics) ? item.topics.slice(0, 5) : [];
  const description = item.description || '';

  return `<article class="result">
    <div>
      <div class="result-title">
        ${avatar ? `<img class="avatar" src="${escapeAttr(avatar)}" alt=""/>` : ''}
        <a href="${escapeAttr(href)}">${escapeHtml(fullName)}</a>
      </div>
      ${description ? `<p class="description">${escapeHtml(description)}</p>` : ''}
      ${topics.length ? `<div class="topics">${topics.map(topic => `<a class="topic" href="/search${buildQueryString({ q: `topic:${topic}`, type: 'repositories' })}">${escapeHtml(topic)}</a>`).join('')}</div>` : ''}
      <div class="meta">
        ${item.language ? `<span><span class="language-dot"></span> ${escapeHtml(item.language)}</span>` : ''}
        <span>Star ${formatCompactNumber(item.stargazers_count)}</span>
        <span>Fork ${formatCompactNumber(item.forks_count)}</span>
        ${item.updated_at ? `<span>Updated ${escapeHtml(formatDate(item.updated_at))}</span>` : ''}
      </div>
    </div>
    <div>
      <a class="star-btn" href="${escapeAttr(href)}/stargazers">Star ${formatCompactNumber(item.stargazers_count)}</a>
    </div>
  </article>`;
}

function buildRepositorySearchFacetHtml(q, items) {
  const languages = Array.from(new Map(items
    .filter(item => item.language)
    .map(item => [item.language, item.language])).values()).slice(0, 10);
  const languageHtml = languages.map(lang => {
    const query = `${q} language:${lang}`.trim();
    return `<a class="facet-link" href="/search${buildQueryString({ q: query, type: 'repositories' })}"><span class="language-dot"></span>${escapeHtml(lang)}</a>`;
  }).join('') || '<span class="muted small">No language facets on this page.</span>';

  return `
    <div class="facet-group">
      <h3 class="facet-heading">Languages</h3>
      ${languageHtml}
    </div>`;
}

function buildSearchScopeFacetHtml(scope) {
  if (!scope) return '';
  return `
    <div class="facet-group">
      <h3 class="facet-heading">Search scope</h3>
      <span class="muted small">${escapeHtml(scope)}</span>
    </div>`;
}

function buildCodeResultHtml(item) {
  const filePath = item.path || item.name || '(file)';
  const fileHref = getGitHubWebPathFromUrl(item.html_url || '');
  const repoFullName = item.repository?.full_name || '';
  const repoPath = repoFullName ? `/${repoFullName}` : getGitHubWebPathFromUrl(item.repository?.html_url || '');
  const repoDisplay = repoFullName || repoPath.replace(/^\//, '');

  return `<article class="result">
    <div>
      <div class="result-title">
        <a href="${escapeAttr(fileHref || '#')}">${escapeHtml(filePath)}</a>
      </div>
      ${repoDisplay ? `<a class="repo-link" href="${escapeAttr(repoPath || '#')}">${escapeHtml(repoDisplay)}</a>` : ''}
      <div class="meta">
        ${item.name ? `<span>${escapeHtml(item.name)}</span>` : ''}
        ${item.score ? `<span>Score ${escapeHtml(Number(item.score).toFixed(2))}</span>` : ''}
      </div>
    </div>
    <div>
      <a class="star-btn" href="${escapeAttr(fileHref || '#')}">Open</a>
    </div>
  </article>`;
}

function buildIssueResultHtml(item) {
  const issuePath = getGitHubWebPathFromUrl(item.html_url || '');
  const repoPath = getRepositoryPathFromApiUrl(item.repository_url || '');
  const repoName = repoPath.replace(/^\//, '');
  const user = item.user?.login || '';
  const state = item.state || 'open';
  const title = item.title || '(untitled)';
  const body = String(item.body || '').replace(/\s+/g, ' ').trim();
  const summary = body.length > 240 ? `${body.slice(0, 237)}...` : body;
  const number = item.number ? `#${item.number}` : '';

  return `<article class="result">
    <div>
      <div class="result-title">
        <span class="state-badge ${state === 'closed' ? 'closed' : ''}">${escapeHtml(state)}</span>
        <a href="${escapeAttr(issuePath || '#')}">${escapeHtml(title)}</a>
      </div>
      ${repoName ? `<a class="repo-link" href="${escapeAttr(repoPath)}">${escapeHtml(repoName)}</a>` : ''}
      ${summary ? `<p class="description">${escapeHtml(summary)}</p>` : ''}
      <div class="meta">
        ${number ? `<span>${escapeHtml(number)}</span>` : ''}
        ${user ? `<span>opened by ${escapeHtml(user)}</span>` : ''}
        <span>${formatCompactNumber(item.comments)} comments</span>
        ${item.updated_at ? `<span>Updated ${escapeHtml(formatDate(item.updated_at))}</span>` : ''}
      </div>
    </div>
    <div>
      <a class="star-btn" href="${escapeAttr(issuePath || '#')}">Open</a>
    </div>
  </article>`;
}

function buildUserResultHtml(item) {
  const login = item.login || '(user)';
  const href = getGitHubWebPathFromUrl(item.html_url || `https://github.com/${login}`);
  const avatar = rewriteOriginalUrlToProxy(item.avatar_url || '');
  const type = item.type || 'User';

  return `<article class="result">
    <div>
      <div class="result-title">
        ${avatar ? `<img class="avatar" src="${escapeAttr(avatar)}" alt=""/>` : ''}
        <a href="${escapeAttr(href || '#')}">${escapeHtml(login)}</a>
      </div>
      <div class="meta">
        <span>${escapeHtml(type)}</span>
        ${item.score ? `<span>Score ${escapeHtml(Number(item.score).toFixed(2))}</span>` : ''}
      </div>
    </div>
    <div>
      <a class="star-btn" href="${escapeAttr(href || '#')}">Open</a>
    </div>
  </article>`;
}

function getGitHubWebPathFromUrl(value) {
  if (!value) return '';
  try {
    const u = new URL(value);
    if (stripPort(u.hostname) === 'github.com') {
      return `${u.pathname}${u.search}`;
    }
  } catch (_) {}
  return rewriteOriginalUrlToProxy(value);
}

function getRepositoryPathFromApiUrl(value) {
  if (!value) return '';
  try {
    const u = new URL(value);
    if (stripPort(u.hostname) !== 'api.github.com') return getGitHubWebPathFromUrl(value);
    const match = u.pathname.match(/^\/repos\/([^/]+)\/([^/]+)$/);
    if (!match) return '';
    return `/${match[1]}/${match[2]}`;
  } catch (_) {
    return '';
  }
}

function buildSearchPagination(q, type, page, pageCount, sort, order) {
  if (!q || pageCount <= 1) return '';
  const links = [];
  const addPage = (p, label = String(p)) => {
    const href = `/search${buildQueryString({ q, type, sort, order: sort ? order : '', p })}`;
    links.push(p === page ? `<span class="active">${escapeHtml(label)}</span>` : `<a href="${escapeAttr(href)}">${escapeHtml(label)}</a>`);
  };

  if (page > 1) addPage(page - 1, 'Previous');
  for (let p = Math.max(1, page - 2); p <= Math.min(pageCount, page + 2); p++) addPage(p);
  if (page < pageCount) addPage(page + 1, 'Next');

  return `<nav class="pagination" aria-label="Pagination">${links.join('')}</nav>`;
}

function parseCommitsPageRequest(pathname, searchParams) {
  const decodedPath = safeDecodeURI(pathname);
  const match = decodedPath.match(/^\/([^/]+)\/([^/]+)\/commits(?:\/(.+))?\/?$/i);
  if (!match) return null;

  const owner = match[1];
  const repo = match[2];
  const refFromPath = (match[3] || '').replace(/\/$/, '');
  const ref = (searchParams.get('sha') || refFromPath || '').trim();
  const pageValue = searchParams.get('p') || searchParams.get('page');
  const page = Math.max(1, Math.min(Number.parseInt(pageValue || '', 10) || (searchParams.has('after') ? 2 : 1), 100));

  return {
    owner,
    repo,
    ref,
    page,
    author: (searchParams.get('author') || '').trim().slice(0, 128),
    since: (searchParams.get('since') || '').trim().slice(0, 64),
    until: (searchParams.get('until') || '').trim().slice(0, 64),
    path: (searchParams.get('path') || searchParams.get('newPath') || '').trim().slice(0, 512),
  };
}

function buildGitHubApiHeaders(env, userAgent = 'gh-proxy-api-ui') {
  const headers = new Headers({
    'accept': 'application/vnd.github+json',
    'user-agent': userAgent,
    'x-github-api-version': '2022-11-28',
  });
  const token = getGitHubToken(env);
  if (token) headers.set('Authorization', `Bearer ${token}`);
  return headers;
}

async function fetchGitHubJson(apiUrl, env, userAgent) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);

  try {
    const resp = await fetch(apiUrl.toString(), {
      method: 'GET',
      headers: buildGitHubApiHeaders(env, userAgent),
      redirect: 'manual',
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    let data = null;
    let error = null;
    try {
      data = await resp.json();
    } catch (_) {
      error = `GitHub returned ${resp.status}.`;
    }

    if (!resp.ok) {
      error = data?.message || error || `GitHub returned ${resp.status}.`;
    }

    return {
      ok: resp.ok,
      status: resp.status,
      data,
      error,
      headers: resp.headers,
      rate: readSearchRateLimit(resp.headers),
    };
  } catch (err) {
    clearTimeout(timeoutId);
    return {
      ok: false,
      status: err.name === 'AbortError' ? 504 : 502,
      data: null,
      error: err.name === 'AbortError' ? 'GitHub Commits API timed out.' : 'GitHub Commits API request failed.',
      headers: new Headers(),
      rate: null,
    };
  }
}

async function handleCommitsRequest(requestInfo, origin, env) {
  const repoApiUrl = new URL(`https://api.github.com/repos/${encodeURIComponent(requestInfo.owner)}/${encodeURIComponent(requestInfo.repo)}`);
  const repoResult = await fetchGitHubJson(repoApiUrl, env, 'gh-proxy-commits-ui');

  if (repoResult.ok && repoResult.data?.private) {
    return htmlResponse(buildNotFoundHtml(), 404, origin);
  }

  const repo = repoResult.ok ? repoResult.data : null;
  const ref = requestInfo.ref || repo?.default_branch || '';
  const perPage = 35;
  let commitsResult = null;

  if (repoResult.ok) {
    const commitsApiUrl = new URL(`https://api.github.com/repos/${encodeURIComponent(requestInfo.owner)}/${encodeURIComponent(requestInfo.repo)}/commits`);
    commitsApiUrl.searchParams.set('per_page', String(perPage));
    commitsApiUrl.searchParams.set('page', String(requestInfo.page));
    if (ref) commitsApiUrl.searchParams.set('sha', ref);
    if (requestInfo.author) commitsApiUrl.searchParams.set('author', requestInfo.author);
    if (requestInfo.since) commitsApiUrl.searchParams.set('since', requestInfo.since);
    if (requestInfo.until) commitsApiUrl.searchParams.set('until', requestInfo.until);
    if (requestInfo.path) commitsApiUrl.searchParams.set('path', requestInfo.path);

    commitsResult = await fetchGitHubJson(commitsApiUrl, env, 'gh-proxy-commits-ui');
  }

  const status = repoResult.ok ? (commitsResult?.ok ? 200 : commitsResult?.status || 502) : repoResult.status;
  return htmlResponse(buildCommitsHtml({
    requestInfo,
    repo,
    ref,
    commits: Array.isArray(commitsResult?.data) ? commitsResult.data : [],
    error: repoResult.error || commitsResult?.error || null,
    rate: commitsResult?.rate || repoResult.rate,
    pagination: parseGitHubPagination(commitsResult?.headers?.get('link') || ''),
  }), status, origin);
}

function parseGitHubPagination(linkHeader) {
  const out = { next: false, prev: false };
  if (!linkHeader) return out;

  for (const part of linkHeader.split(',')) {
    const relMatch = part.match(/rel="([^"]+)"/);
    if (!relMatch) continue;
    if (relMatch[1] === 'next') out.next = true;
    if (relMatch[1] === 'prev') out.prev = true;
  }

  return out;
}

function buildCommitsBasePath(owner, repo, ref) {
  const encodedRef = String(ref || '').split('/').filter(Boolean).map(encodeURIComponent).join('/');
  return `/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/commits${encodedRef ? `/${encodedRef}` : ''}`;
}

function buildCommitsQuery(requestInfo, overrides = {}) {
  return buildQueryString({
    author: requestInfo.author,
    since: requestInfo.since,
    until: requestInfo.until,
    path: requestInfo.path,
    p: requestInfo.page,
    ...overrides,
  });
}

function groupCommitsByDate(commits) {
  const groups = new Map();
  for (const item of commits) {
    const date = item.commit?.committer?.date || item.commit?.author?.date || item.committer?.date || item.author?.date;
    const title = formatDate(date) || 'Unknown date';
    if (!groups.has(title)) groups.set(title, []);
    groups.get(title).push(item);
  }
  return Array.from(groups, ([title, items]) => ({ title, items }));
}

function splitCommitMessage(message) {
  const lines = String(message || '').split(/\r?\n/);
  const subject = lines[0] || '(no commit message)';
  const body = lines.slice(1).join('\n').trim();
  return { subject, body };
}

function buildCommitAuthorHtml(item, owner, repo, ref) {
  const apiUser = item.author || item.committer;
  const commitAuthor = item.commit?.author || item.commit?.committer || {};
  const login = apiUser?.login || '';
  const display = login || commitAuthor.name || 'Unknown author';
  const avatar = rewriteOriginalUrlToProxy(apiUser?.avatar_url || '');
  const authorHref = login ? `/${login}` : '';
  const filterHref = login
    ? `${buildCommitsBasePath(owner, repo, ref)}${buildQueryString({ author: login })}`
    : '';

  return `<span class="commit-author">
    ${avatar ? `<a href="${escapeAttr(authorHref || '#')}"><img class="avatar" src="${escapeAttr(avatar)}" alt="${escapeAttr(display)}"/></a>` : '<span class="avatar avatar-fallback"></span>'}
    ${filterHref ? `<a class="muted-link" href="${escapeAttr(filterHref)}">${escapeHtml(display)}</a>` : `<span>${escapeHtml(display)}</span>`}
  </span>`;
}

function buildCommitRowHtml(item, owner, repo, ref) {
  const sha = item.sha || '';
  const shortSha = sha.slice(0, 7);
  const message = splitCommitMessage(item.commit?.message || '');
  const commitPath = `/${owner}/${repo}/commit/${sha}`;
  const treePath = `/${owner}/${repo}/tree/${sha}`;
  const commitDate = item.commit?.committer?.date || item.commit?.author?.date || '';
  const bodyHtml = message.body ? `<pre class="commit-body">${escapeHtml(message.body)}</pre>` : '';

  return `<li class="commit-row">
    <div class="commit-main">
      <a class="commit-title" href="${escapeAttr(commitPath)}">${escapeHtml(message.subject)}</a>
      ${bodyHtml}
      <div class="commit-meta">
        ${buildCommitAuthorHtml(item, owner, repo, ref)}
        <span>committed</span>
        ${commitDate ? `<time datetime="${escapeAttr(commitDate)}">${escapeHtml(formatDate(commitDate))}</time>` : ''}
      </div>
    </div>
    <div class="commit-actions">
      <a class="sha-link" href="${escapeAttr(commitPath)}">${escapeHtml(shortSha)}</a>
      <button class="icon-btn copy-sha" type="button" data-sha="${escapeAttr(sha)}" aria-label="Copy full SHA for ${escapeAttr(shortSha)}">Copy</button>
      <a class="icon-btn" href="${escapeAttr(treePath)}" aria-label="Browse repository at ${escapeAttr(shortSha)}">Code</a>
    </div>
  </li>`;
}

function buildCommitsHtml({ requestInfo, repo, ref, commits, error, rate, pagination }) {
  const owner = requestInfo.owner;
  const repoName = requestInfo.repo;
  const repoFullName = repo?.full_name || `${owner}/${repoName}`;
  const groups = groupCommitsByDate(commits);
  const basePath = buildCommitsBasePath(owner, repoName, ref);
  const resetHref = basePath;
  const nextHref = `${basePath}${buildCommitsQuery(requestInfo, { p: requestInfo.page + 1 })}`;
  const prevHref = `${basePath}${buildCommitsQuery(requestInfo, { p: Math.max(1, requestInfo.page - 1) })}`;
  const currentPath = requestInfo.path || '';
  const title = `Commits - ${repoFullName}`;
  const rateHtml = rate?.limit ? `<span>API: ${escapeHtml(rate.remaining)}/${escapeHtml(rate.limit)} remaining</span>` : '';
  const errorHtml = error ? `<div class="commits-error">${escapeHtml(error)}</div>` : '';
  const groupHtml = groups.map(group => `
    <section class="commit-group">
      <div class="timeline-dot" aria-hidden="true"></div>
      <h2>Commits on ${escapeHtml(group.title)}</h2>
      <ul class="commit-list">
        ${group.items.map(item => buildCommitRowHtml(item, owner, repoName, ref)).join('')}
      </ul>
    </section>`).join('') || `
    <div class="empty-state">
      <h2>No commits found</h2>
      <p>Try another branch, author, date range, or path.</p>
    </div>`;

  return `<!DOCTYPE html>
<html lang="en" data-color-mode="auto">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${escapeHtml(title)}</title>
<style>
:root {
  color-scheme: light dark;
  --bg: #ffffff;
  --fg: #1f2328;
  --muted: #59636e;
  --border: #d1d9e0;
  --subtle: #f6f8fa;
  --accent: #0969da;
  --success: #1f883d;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117;
    --fg: #e6edf3;
    --muted: #8b949e;
    --border: #30363d;
    --subtle: #161b22;
    --accent: #58a6ff;
    --success: #3fb950;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.topbar {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 14px 24px;
  border-bottom: 1px solid var(--border);
  background: var(--subtle);
}
.mark {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  background: var(--fg);
  color: var(--bg);
  display: grid;
  place-items: center;
  font-weight: 700;
}
.repo-name {
  min-width: 0;
  font-size: 16px;
}
.repo-name span { color: var(--muted); }
.nav {
  display: flex;
  gap: 8px;
  padding: 0 24px;
  border-bottom: 1px solid var(--border);
}
.nav a {
  padding: 12px 4px 10px;
  color: var(--fg);
  border-bottom: 2px solid transparent;
}
.nav a.active {
  font-weight: 600;
  border-bottom-color: #fd8c73;
}
.container {
  max-width: 1180px;
  margin: 0 auto;
  padding: 24px;
}
.page-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 18px;
  padding-bottom: 14px;
  border-bottom: 1px solid var(--border);
}
h1 {
  margin: 0;
  font-size: 24px;
  font-weight: 400;
}
.rate {
  color: var(--muted);
  font-size: 12px;
}
.filters {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: end;
  margin-bottom: 22px;
}
.field {
  display: grid;
  gap: 4px;
}
.field label {
  color: var(--muted);
  font-size: 12px;
  font-weight: 600;
}
.field input {
  min-width: 150px;
  height: 34px;
  padding: 0 10px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--bg);
  color: var(--fg);
  font: inherit;
}
.field.ref input { min-width: 190px; }
.btn, .link-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  height: 34px;
  padding: 0 12px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--subtle);
  color: var(--fg);
  font: inherit;
  cursor: pointer;
}
.timeline {
  position: relative;
  margin-left: 16px;
}
.timeline::before {
  content: "";
  position: absolute;
  top: 0;
  bottom: 0;
  left: 8px;
  width: 2px;
  background: var(--border);
}
.commit-group {
  position: relative;
  padding-left: 36px;
  margin-bottom: 26px;
}
.timeline-dot {
  position: absolute;
  left: 0;
  top: 3px;
  width: 18px;
  height: 18px;
  border: 2px solid var(--border);
  border-radius: 50%;
  background: var(--bg);
}
.commit-group h2 {
  margin: 0 0 10px;
  font-size: 15px;
  font-weight: 500;
}
.commit-list {
  margin: 0;
  padding: 0;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--bg);
  list-style: none;
  overflow: hidden;
}
.commit-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 16px;
  padding: 12px 14px;
  border-top: 1px solid var(--border);
}
.commit-row:first-child { border-top: 0; }
.commit-title {
  display: inline-block;
  max-width: 100%;
  color: var(--fg);
  font-weight: 600;
  overflow-wrap: anywhere;
}
.commit-body {
  max-width: 780px;
  margin: 8px 0 0;
  padding: 10px;
  border-radius: 6px;
  background: var(--subtle);
  color: var(--muted);
  font: 12px/1.45 ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, monospace;
  white-space: pre-wrap;
}
.commit-meta {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
  margin-top: 6px;
  color: var(--muted);
  font-size: 12px;
}
.commit-author {
  display: inline-flex;
  align-items: center;
  gap: 5px;
}
.avatar {
  width: 18px;
  height: 18px;
  border-radius: 50%;
  vertical-align: middle;
}
.avatar-fallback {
  display: inline-block;
  background: var(--border);
}
.muted-link { color: var(--muted); }
.commit-actions {
  display: flex;
  align-items: center;
  gap: 6px;
}
.sha-link, .icon-btn {
  height: 28px;
  display: inline-flex;
  align-items: center;
  padding: 0 8px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--subtle);
  color: var(--fg);
  font-size: 12px;
}
button.icon-btn { cursor: pointer; }
.commits-error, .empty-state {
  margin: 20px 0;
  padding: 24px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--subtle);
}
.commits-error { color: #b42318; font-weight: 600; }
.empty-state h2 {
  margin: 0 0 6px;
  font-size: 18px;
}
.empty-state p {
  margin: 0;
  color: var(--muted);
}
.pagination {
  display: flex;
  justify-content: center;
  gap: 8px;
  margin: 24px 0 4px;
}
.pagination a, .pagination span {
  padding: 7px 12px;
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--fg);
}
.pagination .disabled {
  color: var(--muted);
  opacity: .7;
}
@media (max-width: 760px) {
  .topbar, .page-head { align-items: flex-start; flex-direction: column; }
  .container { padding: 16px; }
  .timeline { margin-left: 0; }
  .commit-row { display: block; }
  .commit-actions { margin-top: 10px; }
  .field, .field input { width: 100%; }
}
</style>
</head>
<body>
<header class="topbar">
  <a class="mark" href="https://${ENTRY_DOMAIN}/" aria-label="GitHub Proxy">GH</a>
  <div class="repo-name"><a href="/${escapeAttr(owner)}">${escapeHtml(owner)}</a><span> / </span><a href="/${escapeAttr(owner)}/${escapeAttr(repoName)}">${escapeHtml(repoName)}</a></div>
</header>
<nav class="nav" aria-label="Repository">
  <a href="/${escapeAttr(owner)}/${escapeAttr(repoName)}">Code</a>
  <a class="active" href="${escapeAttr(basePath)}">Commits</a>
  <a href="/${escapeAttr(owner)}/${escapeAttr(repoName)}/branches">Branches</a>
  <a href="/${escapeAttr(owner)}/${escapeAttr(repoName)}/tags">Tags</a>
</nav>
<main class="container">
  <div class="page-head">
    <h1>Commits</h1>
    <div class="rate">${rateHtml}</div>
  </div>
  <form class="filters" method="get" action="${escapeAttr(basePath)}">
    <div class="field ref">
      <label for="ref-input">Branch or SHA</label>
      <input id="ref-input" name="sha" value="${escapeAttr(ref)}" autocomplete="off"/>
    </div>
    <div class="field">
      <label for="author-input">Author</label>
      <input id="author-input" name="author" value="${escapeAttr(requestInfo.author)}" autocomplete="off"/>
    </div>
    <div class="field">
      <label for="since-input">Since</label>
      <input id="since-input" name="since" type="date" value="${escapeAttr(requestInfo.since.slice(0, 10))}"/>
    </div>
    <div class="field">
      <label for="until-input">Until</label>
      <input id="until-input" name="until" type="date" value="${escapeAttr(requestInfo.until.slice(0, 10))}"/>
    </div>
    <div class="field">
      <label for="path-input">Path</label>
      <input id="path-input" name="path" value="${escapeAttr(currentPath)}" autocomplete="off"/>
    </div>
    <button class="btn" type="submit">Filter</button>
    <a class="link-btn" href="${escapeAttr(resetHref)}">Reset</a>
  </form>
  ${errorHtml}
  <div class="timeline">
    ${groupHtml}
  </div>
  <nav class="pagination" aria-label="Pagination">
    ${requestInfo.page > 1 && pagination.prev ? `<a href="${escapeAttr(prevHref)}">Previous</a>` : '<span class="disabled">Previous</span>'}
    <span>Page ${escapeHtml(requestInfo.page)}</span>
    ${pagination.next ? `<a href="${escapeAttr(nextHref)}">Next</a>` : '<span class="disabled">Next</span>'}
  </nav>
</main>
<script>
document.addEventListener('click', function (event) {
  const button = event.target.closest('.copy-sha');
  if (!button) return;
  const sha = button.getAttribute('data-sha') || '';
  if (!sha) return;
  Promise.resolve(navigator.clipboard && navigator.clipboard.writeText(sha)).then(function () {
    const oldText = button.textContent;
    button.textContent = 'Copied';
    setTimeout(function () { button.textContent = oldText; }, 1200);
  }).catch(function () {});
});
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
  async fetch(request, env) {
    return handleRequest(request, env);
  },
};

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const origin = request.headers.get('Origin') || '';
  const effectiveHost = stripPort(request.headers.get('Host') || url.host);

  if (url.protocol === 'http:') {
    url.protocol = 'https:';
    return Response.redirect(url.toString(), 301);
  }

  if (effectiveHost === ENTRY_DOMAIN) {
    return handleEntryRequest(url, origin, env);
  }

  return handleProxyRequest(request, url, origin, effectiveHost, env);
}

async function handleEntryRequest(url, origin, env) {
  if (url.pathname === '/') {
    return htmlResponse(buildHomeHtml(), 200, origin);
  }
  if (url.pathname === '/search') {
    return handleSearchRequest(url, origin, env);
  }
  if (['/favicon.ico', '/robots.txt'].includes(url.pathname)) {
    return new Response(null, { status: 404 });
  }

  const NOT_FOUND = () => htmlResponse(buildNotFoundHtml(), 404, origin);

  const decodedPath = safeDecodeURI(url.pathname);
  if (
    shouldBlockGithubWebPath('github.com', url.pathname) ||
    shouldBlockGithubWebPath('github.com', decodedPath)
  ) {
    return NOT_FOUND();
  }
  if (ENABLE_STRICT_DEFENSE && (
    shouldBlockStrictDefensePath('github.com', url.pathname) ||
    shouldBlockStrictDefensePath('github.com', decodedPath)
  )) {
    return NOT_FOUND();
  }
  if (hasSensitiveQueryParam(url.search)) {
    return NOT_FOUND();
  }

  const redir = new URL(url);
  redir.host = getProxyHostByOrigin('github.com');
  return Response.redirect(redir.toString(), 302);
}

async function handleProxyRequest(request, url, origin, effectiveHost, env) {
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

  const originalPath = url.pathname;
  const originalSearch = url.search || '';
  const extracted = extractTargetFromPath(originalPath);
  const canonicalPath = extracted?.pathname ?? originalPath;
  const mergedSearch = mergeSearch(originalSearch, extracted?.search || '');

  // 只读代理：允许 GET / HEAD，以及 Git Smart HTTP clone/fetch 所需的 upload-pack POST。
  if (!isAllowedProxyMethod(request, currentOrigin, canonicalPath)) {
    return new Response('Method Not Allowed', {
      status: 405,
      headers: { ...Object.fromEntries(applyCorsHeaders(new Headers(), origin)), 'Allow': 'GET, HEAD, POST, OPTIONS' },
    });
  }

  if (shouldRedirectGithubProxyRootToEntry(request, canonicalPath, currentOrigin)) {
    return Response.redirect(`https://${ENTRY_DOMAIN}/`, 302);
  }

  if (currentOrigin === 'github.com' && canonicalPath === '/search' && request.method === 'GET') {
    const searchUrl = new URL(url);
    searchUrl.pathname = '/search';
    searchUrl.search = mergedSearch;
    return handleSearchRequest(searchUrl, origin, env);
  }

  // 对路径做解码和规范化后再进行敏感路径检测。
  const decodedPath = safeDecodeURI(canonicalPath);
  if (
    shouldBlockGithubWebPath(currentOrigin, canonicalPath) ||
    shouldBlockGithubWebPath(currentOrigin, decodedPath)
  ) {
    return NOT_FOUND();
  }
  if (ENABLE_STRICT_DEFENSE && (
    shouldBlockStrictDefensePath(currentOrigin, canonicalPath) ||
    shouldBlockStrictDefensePath(currentOrigin, decodedPath)
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

  attachGitHubToken(headers, env, request, currentOrigin, pathname);

  // 为上游请求设置超时控制。
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);

  try {
    const resp = await fetch(upstream.href, {
      method: request.method,
      headers,
      body: request.method === 'GET' || request.method === 'HEAD' ? null : request.body,
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
        stripUnsafeResponseHeaders(redirectHeaders);
        return new Response(resp.body, {
          status: resp.status,
          headers: redirectHeaders,
        });
      }
    }

    const respHeaders = new Headers(resp.headers);
    applyCorsHeaders(respHeaders, origin);

    stripUnsafeResponseHeaders(respHeaders);

    if (resp.status === 404) {
      if (wantsHtmlErrorPage(request)) return NOT_FOUND();
      return new Response(request.method === 'HEAD' ? null : resp.body, {
        status: resp.status,
        headers: respHeaders,
      });
    }

    // 直接消费上游响应体并按需改写。
    const body = await modifyResponse(resp);

    return new Response(body, { status: resp.status, headers: respHeaders });
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
