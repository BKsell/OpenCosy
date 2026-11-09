'use strict';

let d = {};

function bindDeps(next) {
  d = next;
}

function fetchSearchSuggestions(query) {
  return new Promise((resolve) => {
    // 模板经内核校验；buildSuggestUrl 返回 null（provider 无建议接口 / 校验失败）
    // 时静默回落空列表，绝不拼接裸 query 构造 URL。
    const url = d.searchProvider.buildSuggestUrl(d.searchProviderId, query);
    if (!url) return resolve([]);
    let settled = false;
    let request;
    try {
      request = d.net.request({ url, redirect: 'error' });
    } catch {
      return resolve([]);
    }
    const finish = (list) => {
      if (!settled) { settled = true; resolve(list); }
    };
    const timer = setTimeout(() => {
      try { request.abort(); } catch {}
      finish([]);
    }, d.SUGGEST_TIMEOUT_MS);

    const chunks = [];
    // 流式字节预算：建议接口是极小 JSON，收到超过上限立即 destroy，不再拼接后续
    // 数据块，避免被异常 / 被劫持接口用超大 body 打爆主进程内存。
    const budget = d.suggestionGuard.createByteBudget(d.suggestionGuard.SUGGEST_DEFAULT_MAX_BYTES);
    let oversized = false;
    request.on('response', (response) => {
      const ct = (response.headers['content-type'] || []).join('').toLowerCase();
      // osjson 正常返回 json；跟随到别的类型直接丢弃。
      if (response.statusCode !== 200 || !ct.includes('json')) {
        clearTimeout(timer);
        try { response.destroy(); } catch {}
        return finish([]);
      }
      response.on('data', (c) => {
        if (oversized) return;
        if (!budget.accept(c)) {
          oversized = true;
          try { response.destroy(); } catch {}
          finish([]);
          return;
        }
        chunks.push(c);
      });
      response.on('end', () => {
        clearTimeout(timer);
        if (oversized) return;
        // 结构固化、逐条消毒 / 去重 / 限量统一走 suggestionguard 内核，
        // 不再在 IPC 里手写 JSON.parse + 字符串判断。
        const parsed = d.suggestionGuard.parseOpenSearchSuggestions(Buffer.concat(chunks), {
          maxBytes: d.suggestionGuard.SUGGEST_DEFAULT_MAX_BYTES,
          maxItems: d.SUGGEST_MAX_ITEMS,
          itemMaxChars: 100,
        });
        finish(parsed.ok ? parsed.suggestions : []);
      });
      response.on('error', () => { clearTimeout(timer); finish([]); });
    });
    request.on('error', () => { clearTimeout(timer); finish([]); });
    try { request.end(); } catch { clearTimeout(timer); finish([]); }
  });
}

function generateUserAgent() {
  const platform = d.os.platform();
  const arch = d.os.arch();
  const release = d.os.release();
  const chromeVersion = process.versions.chrome;
  let osInfo;
  switch (platform) {
    case 'win32':
      if (release.startsWith('10.')) osInfo = 'Windows NT 10.0';
      else if (release.startsWith('6.3')) osInfo = 'Windows NT 6.3';
      else if (release.startsWith('6.2')) osInfo = 'Windows NT 6.2';
      else if (release.startsWith('6.1')) osInfo = 'Windows NT 6.1';
      else if (release.startsWith('6.0')) osInfo = 'Windows NT 6.0';
      else osInfo = 'Windows NT 10.0';
      osInfo += arch === 'x64' ? '; Win64; x64' : '; WOW64';
      break;
    case 'darwin':
      const macVersion = release.split('.').slice(0, 2).join('.');
      osInfo = `Macintosh; Intel Mac OS X ${macVersion.replace('.', '_')}`;
      break;
    case 'linux':
      if (arch === 'x64') osInfo = 'X11; Linux x86_64';
      else if (arch === 'arm64') osInfo = 'X11; Linux aarch64';
      else osInfo = 'X11; Linux i686';
      break;
    default: osInfo = 'X11; Unknown';
  }
  return `Mozilla/5.0 (${osInfo}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeVersion} OpenCosyBrowser/1.0.0`;
}

module.exports = { fetchSearchSuggestions, generateUserAgent, bindDeps };
