# GitHub Proxy (Cloudflare Workers)

## 项目简介

这是一个运行在 Cloudflare Workers 上的 GitHub 公共访问代理。项目使用 `gh.<你的域名>` 作为入口域名，并把真实上游映射到稳定的脱敏代理子域 `p<hash>-gh.<你的域名>`，避免直接在代理域名中暴露 `github`、`githubusercontent` 等关键词。

当前实现以“匿名公开访问”为前提，重点覆盖 GitHub Web 页面、公开 API、Raw 文件、Release/下载资源、Gist、Docs、Status 以及部分公开 NPM 资源。入口域名负责展示首页并承接直达请求，真正的代理流量由哈希子域处理。

## 当前实现的能力

- 稳定哈希子域映射：同一个上游域名始终映射到同一个 `p<hash>-gh` 子域，后续新增白名单时不会影响已有映射。
- 入口页与代理页分离：`gh.<你的域名>` 提供终端风格首页，非首页请求会自动跳转到对应代理子域。
- 自动改写白名单域名：会改写 HTML、CSS、JavaScript、XML、JSON 中的域名引用，保证页面链接、静态资源和 API 请求继续走代理。
- 跨域名自动纠正：如果路径里嵌入了 `https://github.com/...`、`https://raw.githubusercontent.com/...` 之类的目标地址，会自动跳转到正确的代理子域。
- 特殊路径修复：内置 `latest-commit`、`tree-commit-info` 等嵌套 URL 修复逻辑。
- 基础 CORS 支持：处理预检请求，并把跨域所需响应头补齐。
- 安全清洗：会剥离 `Authorization`、真实 IP、转发链等敏感请求头，只保留匿名访问所需的少量 Cookie。
- 只读代理模式：仅允许 GET 和 HEAD 请求，所有写操作（POST/PUT/DELETE/PATCH 等）返回 405，从源头杜绝误操作风险。
- Cache API 缓存层：通过 Cloudflare `caches.default` 缓存上游 200 响应，按内容类型设置不同缓存策略，减少重复请求。默认 TTL 300 秒，可通过配置调整。
- 超时控制：上游请求超时为 15 秒。
- 入口页搜索跳转：首页输入框除支持 `owner/repo` 和完整 URL 外，还支持输入任意关键词直接跳转到 GitHub 搜索结果。
- 可选地域回源：支持按国家/地区直接回源到真实站点，默认开启。

## 默认白名单域名

当前代码里的 `domain_whitelist` 包含以下域名：

- GitHub 主站与 API：`github.com`、`api.github.com`、`gist.github.com`
- 静态资源：`github.githubassets.com`、`assets-cdn.github.com`、`cdn.jsdelivr.net`、`github.global.ssl.fastly.net`
- 下载相关：`codeload.github.com`、`git-lfs.github.com`
- `githubusercontent` 相关：`githubusercontent.com`、`raw.githubusercontent.com`、`gist.githubusercontent.com`、`avatars.githubusercontent.com`、`camo.githubusercontent.com`、`objects.githubusercontent.com`、`media.githubusercontent.com`、`cloud.githubusercontent.com`、`user-images.githubusercontent.com`、`favicons.githubusercontent.com`、`repository-images.githubusercontent.com`、`render.githubusercontent.com`
- GitHub 子站：`docs.github.com`、`education.github.com`、`securitylab.github.com`、`desktop.github.com`、`pages.github.com`
- 状态与公开 NPM 服务：`www.githubstatus.com`、`npmjs.com`、`api.npms.io`

如果上游页面重定向到了未列出的域名，Worker 会记录未命中的重定向目标，此时需要把对应域名补进白名单后重新部署。

## 域名映射示例

假设：

```js
const PROXY_DOMAIN_SUFFIX = 'example.com';
```

那么当前实现生成的部分映射如下：

- 入口主页：`gh.example.com`
- `github.com` -> `p7ja1-gh.example.com`
- `raw.githubusercontent.com` -> `p7yxd-gh.example.com`
- `api.github.com` -> `p5cc3-gh.example.com`
- `gist.github.com` -> `p1ql8-gh.example.com`
- `avatars.githubusercontent.com` -> `pekbh-gh.example.com`

这些哈希映射由域名本身确定性计算得出，不依赖数组顺序。

## 关键配置

主要配置都在 [src/index.js](/workspaces/GithubSiteProxyForCloudflareWorker/src/index.js) 顶部：

```js
const PROXY_DOMAIN_SUFFIX = 'example.com';
const ENABLE_GEO_REDIRECT = true;
const ALLOWED_COUNTRIES = ['CN'];
const ENABLE_STRICT_DEFENSE = true;
const ENABLE_CACHE = true;
const CACHE_TTL = 300;
```

- `PROXY_DOMAIN_SUFFIX`：必填，你自己的主域名。
- `ENABLE_GEO_REDIRECT`：是否把指定地区以外的访问直接跳回真实上游域名，默认 `true`。
- `ALLOWED_COUNTRIES`：仅在开启地域回源时生效，默认只允许 `CN` 继续走代理。
- `ENABLE_STRICT_DEFENSE`：是否额外拦截常见后台、探测、扫描类路径，默认开启。
- `ENABLE_CACHE`：是否启用 Cache API 缓存层，默认 `true`。
- `CACHE_TTL`：缓存默认 TTL（秒），仅在上游无明确 `Cache-Control` 时使用，默认 `300`。

另外还有两个与行为强相关的常量：

- `MAX_REWRITE_SIZE = 5 * 1024 * 1024`：超过 5MB 的文本响应不会做正文改写，直接透传。
- `UPSTREAM_TIMEOUT_MS = 15000`：上游请求超时时间为 15 秒。

## 部署

### Cloudflare Dashboard

1. 在 Cloudflare 控制台创建一个 Worker。
2. 将 [src/index.js](/workspaces/GithubSiteProxyForCloudflareWorker/src/index.js) 的内容粘贴到 Worker 编辑器中。
3. 修改 `PROXY_DOMAIN_SUFFIX` 等配置。
4. 保存并部署。

### DNS 与 Routes

1. 在 Cloudflare DNS 中添加一条开启代理的小黄云 `A` 记录：

| 类型 | 名称 | 地址 | 代理 |
| :--- | :--- | :--- | :--- |
| A | `*` | `192.0.2.1` | 开启 |

`192.0.2.1` 只是占位地址，真实请求仍由 Cloudflare 接管。

2. 在 Worker Routes 中添加两条规则：

- `gh.example.com/*`
- `*-gh.example.com/*`

这里的 `example.com` 需要替换成你自己的域名。当前设计只依赖单级子域，兼容 Cloudflare 免费版证书。

## 使用方式

部署完成后可通过以下方式访问：

- 首页：`https://gh.<你的域名>`
- 直达仓库：`https://gh.<你的域名>/vuejs/core`
- 首页输入框支持四种输入：
  - `owner/repo` — 直达仓库
  - `https://github.com/owner/repo` — 识别 GitHub URL 并跳转
  - 白名单域名 URL（如 `https://avatars.githubusercontent.com/u/123`）— 自动跳转到对应代理子域
  - 任意关键词 — 跳转 GitHub 搜索

入口域名收到非首页请求后，会自动 302 到对应的哈希代理子域。后续页面里涉及的 Raw、头像、静态资源、Docs、Gist、NPM 等白名单域名，也会自动改写到对应代理域名。

## 安全策略与限制

- 只读代理：仅允许 GET/HEAD 请求，POST/PUT/DELETE/PATCH 等写操作直接返回 405。
- 仅支持匿名公开访问，不支持登录、注册、账号设置、通知、组织管理、支付、Copilot、Marketplace 等需要身份态或高风险的页面。
- 会拦截常见敏感查询参数：`return_to`、`redirect_to`、`next`、`continue`、`destination`。
- 会移除 URL 中的 `access_token`、`token` 等参数。
- 会移除 `authorization`、`x-forwarded-*`、`cf-connecting-ip`、`x-real-ip` 等敏感请求头。
- 只允许透传 `_gh_sess` 和 `_octo` 两个匿名访问相关 Cookie，并限制单个值长度。
- 对于超过 5MB 的文本响应，不会做正文替换，因此极大文本页面可能仍保留原始域名引用。
- 项目主要面向浏览器访问与公开资源下载，不能替代 `git clone`、SSH、GitHub CLI 登录态操作。

## 故障排查

1. 访问直接 404：先检查 Worker Routes 是否同时配置了 `gh.<域名>/*` 和 `*-gh.<域名>/*`。
2. 出现证书问题：确认使用的是单级子域，例如 `p1mmyth9b36hjt-gh.example.com`，不要再套一层子域。
3. 页面资源没有走代理：如果是新的上游域名，需要把它加入 [src/index.js](/workspaces/GithubSiteProxyForCloudflareWorker/src/index.js) 里的 `domain_whitelist`。
4. 某些文本内容没有被改写：先确认响应是否超过 `5MB`，超过限制会直接透传。
5. 想按地区自动回源：把 `ENABLE_GEO_REDIRECT` 改为 `true`，并按需调整 `ALLOWED_COUNTRIES` 后重新部署。

## 免责声明

此项目仅用于教育、研究和改善公开资源访问体验。使用者应自行评估合规性，并遵守当地法律法规与 GitHub 服务条款。
