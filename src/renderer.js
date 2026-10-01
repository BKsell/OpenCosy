const ALLOWED_PROTOCOLS = new Set(['http:', 'https:', 'file:', 'cosy:']);

function isSafeUrl(url) {
  try {
    const parsed = new URL(url);
    return ALLOWED_PROTOCOLS.has(parsed.protocol);
  } catch {
    return false;
  }
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function getSettings() {
  try {
    return JSON.parse(localStorage.getItem('cosySettings') || '{}');
  } catch (e) {
    console.error('解析设置失败:', e);
    return {};
  }
}

// 地址栏搜索 bang：以 "!缩写 关键词" 开头时强制走指定引擎，无视默认搜索引擎。
// 缩写小写匹配；只认开头第一个空白前的 token。
const SEARCH_BANGS = {
  g: ['Google', 'https://www.google.com/search?q='],
  google: ['Google', 'https://www.google.com/search?q='],
  b: ['百度', 'https://www.baidu.com/s?wd='],
  baidu: ['百度', 'https://www.baidu.com/s?wd='],
  bing: ['Bing', 'https://www.bing.com/search?q='],
  y: ['YouTube', 'https://www.youtube.com/results?search_query='],
  yt: ['YouTube', 'https://www.youtube.com/results?search_query='],
  w: ['维基百科', 'https://zh.wikipedia.org/w/index.php?search='],
  wiki: ['维基百科', 'https://zh.wikipedia.org/w/index.php?search='],
  z: ['知乎', 'https://www.zhihu.com/search?type=content&q='],
  zhihu: ['知乎', 'https://www.zhihu.com/search?type=content&q='],
  gh: ['GitHub', 'https://github.com/search?q='],
  github: ['GitHub', 'https://github.com/search?q='],
  tb: ['淘宝', 'https://s.taobao.com/search?q='],
  map: ['地图', 'https://www.bing.com/maps?q='],
};

// ===== IDN 同形异义字（仿冒域名）警示 =====
// 钓鱼者常用西里尔/希腊字母伪装拉丁域名（如 аmаzоn）。这里只做启发式提示，
// 不阻断：含非 ASCII 主机名且标签内混用多套文字（scripts）时要求用户确认。
const SCRIPT_RANGES = [
  [0x0041, 0x007A, 'Latin'],        // 基本拉丁 + 拉丁补充
  [0x0400, 0x052F, 'Cyrillic'],
  [0x0370, 0x03FF, 'Greek'],
  [0x0590, 0x05FF, 'Hebrew'],
  [0x0600, 0x06FF, 'Arabic'],
  [0x4E00, 0x9FFF, 'CJK'],
  [0x3040, 0x30FF, 'Kana'],
  [0x0E00, 0x0E7F, 'Thai'],
];

function codeScript(code) {
  for (const [lo, hi, name] of SCRIPT_RANGES) {
    if (code >= lo && code <= hi) return name;
  }
  return null;
}

// 常见与拉丁字母视觉相同的西里尔 / 希腊小写字符。键为 Unicode 码点，
// 值为它伪装成的拉丁字母。仅收录字形在常见字体下几乎无法分辨的那批，
// 控制误报：像亚马逊这种全拉丁品牌被混入一两个西里尔字母时能被点名。
const CONFUSABLE_TO_LATIN = new Map([
  [0x0430, 'a'], [0x0435, 'e'], [0x043E, 'o'], [0x0440, 'p'],
  [0x0441, 'c'], [0x0443, 'y'], [0x0445, 'x'], [0x0456, 'i'],
  [0x0458, 'j'], [0x04BB, 'h'], [0x04CF, 'l'], [0x04B9, 'u'],
  [0x03B1, 'a'], [0x03BF, 'o'], [0x03C1, 'p'], [0x03C5, 'u'],
  [0x03BA, 'k'], [0x03B5, 'e'], [0x03C4, 't'], [0x03B9, 'i'],
]);

// 标签里只要出现"形似拉丁的非 ASCII 字符"且同时存在真 ASCII 字母，
// 基本可判定为有人故意拿外来字母拼拉丁词，是更强的同形字信号。
function hasLatinLookalikeMix(label) {
  let asciiLetters = 0;
  let lookalikes = 0;
  for (const ch of label) {
    const code = ch.codePointAt(0);
    if ((code >= 0x41 && code <= 0x5A) || (code >= 0x61 && code <= 0x7A)) asciiLetters++;
    else if (CONFUSABLE_TO_LATIN.has(code)) lookalikes++;
  }
  return asciiLetters > 0 && lookalikes > 0;
}

// 返回可疑标签数组；空数组表示看起来正常。
function findSpoofLabels(hostname) {
  const suspicious = [];
  for (const label of hostname.split('.')) {
    if (!label || /^xn--/.test(label)) continue; // punycode 已由浏览器处理
    const scripts = new Set();
    let nonAscii = 0;
    for (const ch of label) {
      const code = ch.codePointAt(0);
      if (code > 0x7F) nonAscii++;
      const s = codeScript(code);
      if (s) scripts.add(s);
    }
    // 同时出现拉丁与其他文字（且存在非 ASCII），是典型同形字混用特征；
    // 全西里尔/希腊的 IDN 名（如纯俄文站）不误报，只有混入拉丁才提示。
    if (nonAscii > 0 && scripts.has('Latin') && scripts.size > 1) suspicious.push(label);
    // 更强信号：一个标签里真拉丁字母 + 形似拉丁的西里尔/希腊字母混排。
    else if (hasLatinLookalikeMix(label)) suspicious.push(label);
  }
  return suspicious;
}

function isLikelySpoofUrl(rawUrl) {
  try {
    const u = new URL(rawUrl);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    const bad = findSpoofLabels(u.hostname);
    return bad.length ? { hostname: u.hostname, labels: bad } : null;
  } catch {
    return null;
  }
}

// 解析 bang，返回 null 表示不是 bang 查询；返回 { url } 表示已拼好目标地址。
function resolveSearchBang(input) {
  if (!input || input.charCodeAt(0) !== 0x21 /* ! */) return null;
  const sp = input.search(/\s/);
  if (sp < 0) return null; // 必须带空格 + 关键词，避免把 "!foo" 当裸词
  const tag = input.slice(1, sp).toLowerCase();
  const engine = SEARCH_BANGS[tag];
  if (!engine) return null;
  const query = input.slice(sp + 1).trim();
  if (!query) return null;
  return { url: engine[1] + encodeURIComponent(query), engine: engine[0] };
}

window.electron = {
  minimize: () => window.electronAPI.minimize(),
  maximize: () => window.electronAPI.maximize(),
  close: () => window.electronAPI.close(),
};

class TabManager {
  constructor() {
    this.tabs = [];
    this.currentTabId = null;
    this.bookmarks = [];
    this.history = [];
    this.findBarVisible = false;
    this.initialize();
  }

  initialize() {
    this.setupEventListeners();
    this.setupIpcListeners();
    this.loadAndApplyThemeColor();
    this.loadBookmarks();
    this.loadHistory();
    this.setupFindBar();
  }

  loadAndApplyThemeColor() {
    try {
      const settings = getSettings();
      if (settings.themeColor) {
        this.applyThemeColor(settings.themeColor);
      } else {
        window.electronAPI.send('get-settings');
        this.applyThemeColor();
      }
    } catch (e) {
      console.error('加载主题颜色失败:', e);
      this.applyThemeColor();
    }
  }

  async loadBookmarks() {
    try {
      const result = await window.electronAPI.invoke('get-bookmarks');
      if (result.success) this.bookmarks = result.bookmarks;
    } catch (e) {
      console.error('加载书签失败:', e);
    }
  }

  async loadHistory() {
    try {
      const result = await window.electronAPI.invoke('get-history');
      if (result.success) this.history = result.history;
    } catch (e) {
      console.error('加载历史记录失败:', e);
    }
  }

  applyThemeColor(color = '#0078d4') {
    document.documentElement.style.setProperty('--theme-color', color);
  }

  showToast(message) {
    let toast = document.getElementById('toast-notification');
    if (!toast) {
      toast = document.createElement('div');
      toast.id = 'toast-notification';
      toast.className = 'cosy-toast';
      document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.classList.add('show');
    setTimeout(() => { toast.classList.remove('show'); }, 2000);
  }

  setupEventListeners() {
    document.getElementById('add-tab').addEventListener('click', () => this.createNewTab());
    document.getElementById('new-tab').addEventListener('click', () => this.createNewTab());
    document.getElementById('settings').addEventListener('click', () => this.createNewTab('cosy://setting'));
    document.getElementById('downloads').addEventListener('click', () => this.createNewTab('cosy://downloadlist'));
    document.getElementById('bookmarks').addEventListener('click', () => this.showBookmarksBar());
    document.getElementById('history').addEventListener('click', () => this.showHistoryPanel());
    document.getElementById('url-input').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        if (e.ctrlKey) {
          const inp = e.currentTarget;
          let v = inp.value.trim();
          if (v && !/\./.test(v)) inp.value = v + '.com';
        }
        this.navigateFromAddressBar();
      }
    });
    document.getElementById('go').addEventListener('click', () => this.navigateFromAddressBar());
    document.getElementById('back').addEventListener('click', () => this.goBack());
    document.getElementById('forward').addEventListener('click', () => this.goForward());
    document.getElementById('refresh').addEventListener('click', () => this.refresh());
    document.getElementById('home').addEventListener('click', () => this.navigateCurrentTab('cosy://newtab'));
    document.getElementById('minimize').addEventListener('click', () => window.electron.minimize());
    document.getElementById('maximize').addEventListener('click', () => window.electron.maximize());
    document.getElementById('close').addEventListener('click', () => window.electron.close());

    const collapseTabbarBtn = document.getElementById('collapse-tabbar');
    if (collapseTabbarBtn) collapseTabbarBtn.addEventListener('click', () => this.toggleTabBarCollapse());
    document.getElementById('more-options').addEventListener('click', (event) => this.showMoreOptionsMenu(event));
    this.setupContextMenu();
  }

  setupIpcListeners() {
    window.electronAPI.on('tab-created', (tabData) => this.addTabToUI(tabData));
    window.electronAPI.on('tab-updated', (tabData) => this.updateTabUI(tabData));
    window.electronAPI.on('tab-loading', (tabData) => this.setTabLoading(tabData.id, tabData.loading));
    window.electronAPI.on('tab-switched', (tabData) => this.switchToTabUI(tabData.id));
    window.electronAPI.on('tab-closed', (tabIndex) => this.removeTabFromUI(tabIndex));
    window.electronAPI.on('tab-audio-changed', (data) => this.updateTabAudio(data));
    window.electronAPI.on('popup-blocked', () => this.showToast('已拦截一个弹出窗口（疑似弹窗轰炸）'));
    window.electronAPI.on('permission-request', (data) => this.handlePermissionRequest(data));
    window.electronAPI.on('html-fullscreen-changed', (data) => this.toggleFullscreenUI(data.isFullscreen));
    window.electronAPI.on('update-theme-color', (color) => this.applyThemeColor(color));
    window.electronAPI.on('settings-loaded', (settings) => { if (settings.themeColor) this.applyThemeColor(settings.themeColor); });
    window.electronAPI.on('bookmarks-updated', (bookmarks) => {
      this.bookmarks = bookmarks;
      this.showBookmarksBar();
    });
    window.electronAPI.on('show-toast', (message) => this.showToast(message));
    window.electronAPI.on('focus-address-bar', () => this.focusAddressBar());
    window.electronAPI.on('show-history', () => this.showHistoryPanel());
    window.electronAPI.on('show-find-bar', () => this.toggleFindBar());
    window.electronAPI.on('show-clear-data-dialog', () => this.showClearDataDialog());
    window.electronAPI.on('renderer-gone', (data) => showCrashInfobar(data || {}));
    window.electronAPI.on('renderer-unresponsive', (data) => showUnresponsiveInfobar(data || {}));
    window.electronAPI.on('renderer-responsive', () => hideRecoveryInfobar());
    window.electronAPI.on('gpu-process-gone', () => {
      this.showToast('GPU 进程崩溃，已自动重启图形进程');
    });
    window.electronAPI.on('trackers-blocked', (data) => updateTrackerShield(data || {}));
    window.electronAPI.on('spoof-warning', (data) => showSpoofWarning(data || {}));
    // 内存节省：标签被休眠时变灰并提示，唤醒（切回重载）后恢复。
    window.electronAPI.on('tab-discarded', (data) => this.markTabDiscarded(data && data.id, true));
    window.electronAPI.on('tab-reloaded', (data) => this.markTabDiscarded(data && data.id, false));
  }

  // markTabDiscarded 切换标签的"已休眠"视觉态。
  // 休眠标签仍可点击（switchToTab 会自动唤醒），所以只改外观、不拦截点击。
  markTabDiscarded(tabId, discarded) {
    if (tabId === undefined || tabId === null) return;
    const el = document.querySelector(`[data-tab-id="${tabId}"]`);
    if (!el) return;
    el.classList.toggle('discarded', !!discarded);
    if (discarded) {
      el.style.opacity = '0.55';
      el.title = '此标签已休眠以释放内存，点击即可重新加载';
    } else {
      el.style.opacity = '';
      el.title = '';
    }
  }

  toggleFullscreenUI(isFullscreen) {
    const elements = ['.titlebar', '.toolbar', '.tab-bar', '.status-bar'];
    elements.forEach(selector => {
      const el = document.querySelector(selector);
      if (el) el.style.display = isFullscreen ? 'none' : 'flex';
    });
  }

  setupFindBar() {
    let findBar = document.getElementById('find-bar');
    if (!findBar) {
      findBar = document.createElement('div');
      findBar.id = 'find-bar';
      findBar.className = 'find-bar';
      findBar.innerHTML = `
        <input type="text" id="find-input" placeholder="在页面中查找..." />
        <span id="find-match-count" class="find-match-count" style="min-width:46px;text-align:center;color:#666;font-size:12px;user-select:none;"></span>
        <button id="find-prev" class="find-btn" title="上一个">▲</button>
        <button id="find-next" class="find-btn" title="下一个">▼</button>
        <button id="find-close" class="find-btn find-close" title="关闭 (Esc)">×</button>
      `;
      document.body.appendChild(findBar);

      // 主进程把活动标签的 found-in-page 结果转发过来，显示“第 x / y 个匹配”。
      // 0 个匹配时给出明确提示，和 Chrome 查找栏行为一致。
      window.electronAPI.on('found-in-page-result', (result) => {
        const el = document.getElementById('find-match-count');
        if (!el || !this.findBarVisible) return;
        const total = result && result.matches;
        if (!total) {
          el.textContent = '无匹配';
          el.style.color = '#d13438';
          return;
        }
        el.textContent = `${result.activeMatchOrdinal}/${total}`;
        el.style.color = '#666';
      });

      const findInput = document.getElementById('find-input');
      // 输入即搜（现代浏览器行为）：内容变化就重新查找并重置计数。
      let findInputTimer = null;
      findInput.addEventListener('input', () => {
        const el = document.getElementById('find-match-count');
        if (el) { el.textContent = ''; el.style.color = '#666'; }
        const value = findInput.value;
        if (findInputTimer) clearTimeout(findInputTimer);
        if (!value) return;
        findInputTimer = setTimeout(() => this.performFind(value, true), 120);
      });
      findInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          const forward = !e.shiftKey;
          this.performFind(findInput.value, forward);
        } else if (e.key === 'Escape') {
          this.hideFindBar();
        }
      });

      document.getElementById('find-next').addEventListener('click', () => { this.performFind(findInput.value, true); });
      document.getElementById('find-prev').addEventListener('click', () => { this.performFind(findInput.value, false); });
      document.getElementById('find-close').addEventListener('click', () => { this.hideFindBar(); });
    }
  }

  toggleFindBar() {
    const findBar = document.getElementById('find-bar');
    if (!findBar) return;
    if (this.findBarVisible) {
      this.hideFindBar();
    } else {
      findBar.classList.add('visible');
      const findInput = document.getElementById('find-input');
      findInput.focus();
      findInput.select();
      this.findBarVisible = true;
    }
  }

  hideFindBar() {
    const findBar = document.getElementById('find-bar');
    if (findBar) findBar.classList.remove('visible');
    const countEl = document.getElementById('find-match-count');
    if (countEl) { countEl.textContent = ''; countEl.style.color = '#666'; }
    this.findBarVisible = false;
    window.electronAPI.send('stop-find');
  }

  performFind(text, forward) {
    if (!text) return;
    const countEl = document.getElementById('find-match-count');
    if (countEl) { countEl.textContent = '…'; countEl.style.color = '#666'; }
    window.electronAPI.send('find-in-page', { text, forward });
  }

  attachOutsideClickClose(panel) {
    setTimeout(() => {
      const closeHandler = (e) => {
        if (!panel.contains(e.target)) {
          panel.remove();
          document.removeEventListener('click', closeHandler);
        }
      };
      setTimeout(() => document.addEventListener('click', closeHandler), 100);
    });
  }

  buildPanelItem(title, url) {
    const item = document.createElement('div');
    item.className = 'cosy-panel-item';
    item.innerHTML = `<strong class="cosy-panel-title">${escapeHtml(title)}</strong><br><small class="cosy-panel-url">${escapeHtml(url)}</small>`;
    return item;
  }

  showBookmarksBar() {
    const existing = document.getElementById('bookmarks-bar');
    if (existing) { existing.remove(); return; }

    const bar = document.createElement('div');
    bar.id = 'bookmarks-bar';
    bar.className = 'cosy-panel';

    if (this.bookmarks.length === 0) {
      bar.innerHTML = '<div class="cosy-panel-empty">暂无书签，按 Ctrl+D 添加书签</div>';
    } else {
      this.bookmarks.forEach(bookmark => {
        const item = this.buildPanelItem(bookmark.title, bookmark.url);
        item.onclick = () => {
          this.createNewTab(bookmark.url);
          bar.remove();
        };
        bar.appendChild(item);
      });
    }

    document.body.appendChild(bar);
    this.attachOutsideClickClose(bar);
  }

  showHistoryPanel() {
    const existing = document.getElementById('history-panel');
    if (existing) { existing.remove(); return; }

    this.loadHistory();

    const panel = document.createElement('div');
    panel.id = 'history-panel';
    panel.className = 'cosy-panel';
    panel.style.right = '60px';

    const header = document.createElement('div');
    header.className = 'cosy-panel-header';
    header.innerHTML = '<strong class="cosy-panel-title">历史记录</strong>';
    const clearBtn = document.createElement('button');
    clearBtn.textContent = '清除历史';
    clearBtn.className = 'cosy-panel-clear-btn';
    clearBtn.onclick = async () => {
      await window.electronAPI.invoke('clear-history');
      this.history = [];
      panel.remove();
      this.showToast('历史记录已清除');
    };
    header.appendChild(clearBtn);
    panel.appendChild(header);

    if (this.history.length === 0) {
      panel.innerHTML += '<div class="cosy-panel-empty">暂无历史记录</div>';
    } else {
      this.history.forEach(item => {
        const entry = this.buildPanelItem(item.title, item.url);
        entry.onclick = () => {
          this.createNewTab(item.url);
          panel.remove();
        };
        panel.appendChild(entry);
      });
    }

    document.body.appendChild(panel);
    this.attachOutsideClickClose(panel);
  }

  showClearDataDialog() {
    const existing = document.getElementById('clear-data-overlay');
    if (existing) { existing.remove(); return; }

    const overlay = document.createElement('div');
    overlay.id = 'clear-data-overlay';
    overlay.className = 'cosy-overlay';
    overlay.innerHTML = `
      <div class="cosy-dialog" style="max-width:400px;">
        <h3 style="margin:0 0 16px;font-size:18px;">清除浏览数据</h3>
        <label style="display:flex;align-items:center;gap:8px;margin-bottom:10px;cursor:pointer;">
          <input type="checkbox" id="clear-cache" checked /> 缓存图片和文件
        </label>
        <label style="display:flex;align-items:center;gap:8px;margin-bottom:10px;cursor:pointer;">
          <input type="checkbox" id="clear-cookies" checked /> Cookie 和网站数据（含 localStorage/IndexedDB）
        </label>
        <label style="display:flex;align-items:center;gap:8px;margin-bottom:10px;cursor:pointer;">
          <input type="checkbox" id="clear-history-cb" checked /> 浏览历史记录
        </label>
        <label style="display:flex;align-items:center;gap:8px;margin-bottom:20px;cursor:pointer;">
          <input type="checkbox" id="clear-downloads-cb" /> 下载列表
        </label>
        <div style="display:flex;gap:8px;justify-content:flex-end;">
          <button id="clear-data-cancel" class="cosy-btn">取消</button>
          <button id="clear-data-confirm" class="cosy-btn-primary">清除数据</button>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);

    overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
    overlay.querySelector('#clear-data-cancel').onclick = () => overlay.remove();
    overlay.querySelector('#clear-data-confirm').onclick = async () => {
      const options = {
        cache: overlay.querySelector('#clear-cache').checked,
        cookies: overlay.querySelector('#clear-cookies').checked,
        history: overlay.querySelector('#clear-history-cb').checked,
        downloads: overlay.querySelector('#clear-downloads-cb').checked,
      };
      overlay.querySelector('#clear-data-confirm').textContent = '清除中...';
      try {
        await window.electronAPI.invoke('clear-browsing-data', options);
        this.showToast('浏览数据已清除');
      } catch (e) {
        this.showToast('清除失败: ' + e.message);
      }
      overlay.remove();
    };
  }

  async createNewTab(url) {
    const settings = getSettings();
    const defaultTab = settings.defaultTab || 'newtab';
    const customUrl = settings.customUrl || '';

    if (!url) {
      switch (defaultTab) {
        case 'bing': url = 'https://www.bing.com'; break;
        case 'custom': url = (customUrl && isSafeUrl(customUrl)) ? customUrl : 'cosy://newtab'; break;
        case 'newtab':
        default: url = 'cosy://newtab'; break;
      }
    }

    if (!isSafeUrl(url)) url = 'cosy://newtab';

    try {
      return await window.electronAPI.invoke('create-tab', url);
    } catch (e) {
      console.error('创建标签页失败:', e);
    }
  }

  createFaviconElement(tabData) {
    const faviconContainer = document.createElement('div');
    faviconContainer.className = 'favicon-container';

    let faviconText = 'N';
    if (tabData.title && tabData.title.trim()) faviconText = tabData.title.trim().charAt(0);

    const textFavicon = document.createElement('div');
    textFavicon.className = 'text-favicon';
    textFavicon.style.display = tabData.favicon && isSafeUrl(tabData.favicon) ? 'none' : 'flex';
    textFavicon.textContent = faviconText;

    faviconContainer.appendChild(textFavicon);

    if (tabData.favicon && isSafeUrl(tabData.favicon)) {
      const imgFavicon = document.createElement('img');
      imgFavicon.className = 'tab-favicon';
      imgFavicon.src = tabData.favicon;
      imgFavicon.alt = '';
      imgFavicon.onerror = function() {
        this.style.display = 'none';
        textFavicon.style.display = 'flex';
      };
      faviconContainer.appendChild(imgFavicon);
    }

    return faviconContainer;
  }

  addTabToUI(tabData) {
    const tabsContainer = document.getElementById('tabs-container');
    const tabElement = document.createElement('div');
    tabElement.className = 'tab';
    tabElement.setAttribute('data-tab-id', tabData.id);
    // 从 get-all-tabs 重建标签栏时，保留休眠标签的视觉态（刷新后不丢）。
    if (tabData.discarded) {
      tabElement.classList.add('discarded');
      tabElement.style.opacity = '0.55';
      tabElement.title = '此标签已休眠以释放内存，点击即可重新加载';
    }

    tabElement.appendChild(this.createFaviconElement(tabData));

    const titleSpan = document.createElement('span');
    titleSpan.className = 'tab-title';
    titleSpan.textContent = tabData.title || '';

    // 音频指示：发声时显示喇叭，静音时显示带斜杠的喇叭；点击切换静音。
    const audioBtn = document.createElement('button');
    audioBtn.className = 'tab-audio-indicator';
    audioBtn.title = '点击静音标签页';
    audioBtn.textContent = '🔊';
    audioBtn.style.cssText = 'display:none;border:none;background:none;cursor:pointer;padding:0 2px;font-size:12px;line-height:1;flex-shrink:0;';
    audioBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const tab = this.tabs.find(t => t.id === tabData.id);
      const nextMuted = !(tab && tab.muted);
      window.electronAPI.invoke('set-tab-muted', { tabId: tabData.id, muted: nextMuted });
    });

    const closeBtn = document.createElement('button');
    closeBtn.className = 'tab-close';
    closeBtn.textContent = '×';
    closeBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      this.closeTab(tabData.id);
    });

    tabElement.appendChild(titleSpan);
    tabElement.appendChild(audioBtn);
    tabElement.appendChild(closeBtn);

    tabElement.addEventListener('click', (e) => {
      if (!e.target.classList.contains('tab-close')) this.switchToTab(tabData.id);
    });

    tabsContainer.appendChild(tabElement);
    this.tabs.push(tabData);
    if (this.tabs.length === 1) this.switchToTab(tabData.id);
  }

  async switchToTab(tabId) {
    const tabIndex = this.tabs.findIndex(t => t.id === tabId);
    if (tabIndex !== -1) {
      await window.electronAPI.invoke('switch-tab', tabIndex);
      this.currentTabId = tabId;
      this.updateTabSelection();
      this.updateAddressBar();
    }
  }

  switchToTabUI(tabId) {
    this.currentTabId = tabId;
    this.updateTabSelection();
    this.updateAddressBar();
    this.updateTitlebarTitle();
  }

  // 主进程音频状态回调：更新数据与标签上的喇叭图标。
  updateTabAudio({ id, audible, muted }) {
    const tab = this.tabs.find(t => t.id === id);
    if (tab) { tab.audible = audible; tab.muted = muted; }
    const el = document.querySelector(`[data-tab-id="${id}"] .tab-audio-indicator`);
    if (!el) return;
    if (muted) {
      el.style.display = '';
      el.textContent = '🔇';
      el.title = '取消静音标签页';
    } else if (audible) {
      el.style.display = '';
      el.textContent = '🔊';
      el.title = '静音标签页';
    } else {
      el.style.display = 'none';
    }
  }

  // 主进程转来的敏感权限请求（摄像头/麦克风/定位/通知/MIDI）。
  // 旧版本这些权限在主进程被静默允许，这里给一个页面内询问条，默认拒绝。
  handlePermissionRequest({ requestId, tabId, permission, origin, mediaTypes }) {
    if (requestId === undefined || requestId === null) return;
    // 同一请求只弹一次
    if (document.getElementById('cosy-perm-' + requestId)) return;

    const PERMISSION_TEXT = {
      media: '使用摄像头和麦克风',
      geolocation: '获取你的位置信息',
      notifications: '发送通知',
      midi: '访问 MIDI 设备',
      midiSysex: '访问 MIDI 设备（含系统专有消息）',
    };
    if (Array.isArray(mediaTypes) && mediaTypes.length) {
      const hasVideo = mediaTypes.includes('video');
      const hasAudio = mediaTypes.includes('audio');
      if (hasVideo && hasAudio) PERMISSION_TEXT.media = '使用摄像头和麦克风';
      else if (hasVideo) PERMISSION_TEXT.media = '使用摄像头';
      else if (hasAudio) PERMISSION_TEXT.media = '使用麦克风';
    }
    const desc = PERMISSION_TEXT[permission] || ('使用「' + permission + '」权限');
    const host = (() => { try { return origin ? new URL(origin).host : '当前页面'; } catch { return '当前页面'; } })();

    const bar = document.createElement('div');
    bar.id = 'cosy-perm-' + requestId;
    bar.style.cssText = 'position:fixed;left:50%;transform:translateX(-50%);bottom:52px;z-index:10004;display:flex;align-items:center;gap:12px;max-width:92vw;padding:10px 14px;background:var(--bg,#fff);color:var(--fg,#222);border:1px solid rgba(0,0,0,.15);border-radius:10px;box-shadow:0 10px 32px rgba(0,0,0,.25);font:13px/1.5 system-ui,sans-serif;';

    const icon = document.createElement('span');
    icon.textContent = '🔒';
    icon.style.fontSize = '16px';
    const msg = document.createElement('div');
    msg.style.minWidth = '0';
    const line1 = document.createElement('div');
    line1.textContent = host + ' 想要' + desc;
    const line2 = document.createElement('div');
    line2.textContent = '仅在你信任该网站时允许';
    line2.style.cssText = 'font-size:11px;opacity:.6;';
    msg.appendChild(line1);
    msg.appendChild(line2);

    const mkBtn = (text, granted, primary) => {
      const b = document.createElement('button');
      b.textContent = text;
      b.style.cssText = 'flex-shrink:0;padding:5px 14px;border-radius:6px;cursor:pointer;border:1px solid rgba(0,0,0,.2);background:' + (primary ? '#0078d4' : 'transparent') + ';color:' + (primary ? '#fff' : 'inherit') + ';';
      b.addEventListener('click', () => {
        window.electronAPI.invoke('permission-response', { requestId, granted });
        bar.remove();
      });
      return b;
    };
    const deny = mkBtn('阻止', false, false);
    const allow = mkBtn('允许', true, true);

    bar.appendChild(icon);
    bar.appendChild(msg);
    bar.appendChild(deny);
    bar.appendChild(allow);
    document.body.appendChild(bar);
  }

  updateTabSelection() {
    document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
    const currentTab = document.querySelector(`[data-tab-id="${this.currentTabId}"]`);
    if (currentTab) currentTab.classList.add('active');
  }

  updateFavicon(tabElement, tabData) {
    const existingContainer = tabElement.querySelector('.favicon-container');
    if (existingContainer) existingContainer.remove();
    const newContainer = this.createFaviconElement(tabData);
    tabElement.insertBefore(newContainer, tabElement.firstChild);
  }

  updateTabUI(tabData) {
    const tabElement = document.querySelector(`[data-tab-id="${tabData.id}"]`);
    if (tabElement) {
      if (tabData.title) {
        const titleElement = tabElement.querySelector('.tab-title');
        if (titleElement) titleElement.textContent = tabData.title;

        const textFavicon = tabElement.querySelector('.text-favicon');
        if (textFavicon) {
          let faviconText = 'N';
          if (tabData.title && tabData.title.trim()) faviconText = tabData.title.trim().charAt(0);
          textFavicon.textContent = faviconText;
        }
      }
      if (tabData.favicon !== undefined) this.updateFavicon(tabElement, tabData);
    }

    const tabIndex = this.tabs.findIndex(t => t.id === tabData.id);
    if (tabIndex !== -1) {
      if (tabData.title) this.tabs[tabIndex].title = tabData.title;
      if (tabData.favicon) this.tabs[tabIndex].favicon = tabData.favicon;
      if (tabData.url) this.tabs[tabIndex].url = tabData.url;
    }

    if (tabData.id === this.currentTabId) {
      this.updateAddressBar();
      this.updateTitlebarTitle();
    }
  }

  setTabLoading(tabId, loading) {
    const tabElement = document.querySelector(`[data-tab-id="${tabId}"]`);
    if (tabElement) tabElement.classList.toggle('loading', loading);
  }

  async closeTab(tabId) {
    const tabIndex = this.tabs.findIndex(t => t.id === tabId);
    if (tabIndex !== -1) await window.electronAPI.invoke('close-tab', tabIndex);
  }

  removeTabFromUI(tabIndex) {
    const tabElement = document.querySelectorAll('.tab')[tabIndex];
    if (tabElement) tabElement.remove();
    this.tabs.splice(tabIndex, 1);
    if (this.tabs.length > 0) {
      const newCurrentTab = this.tabs[Math.min(tabIndex, this.tabs.length - 1)];
      this.switchToTab(newCurrentTab.id);
    }
  }

  async navigateCurrentTab(url) {
    if (!this.currentTabId) return;
    if (!isSafeUrl(url)) url = 'cosy://newtab';
    const formattedUrl = this.formatUrl(url);
    const spoof = isLikelySpoofUrl(formattedUrl);
    if (spoof) {
      const ok = window.confirm(
        '安全提示：该网址的域名 "' + spoof.hostname + '" 混用了不同文字的字符，\n'
        + '可能是用相似字母伪装的仿冒（钓鱼）网站。\n\n'
        + '仍要继续访问吗？'
      );
      if (!ok) return;
    }
    const tabIndex = this.tabs.findIndex(t => t.id === this.currentTabId);
    if (tabIndex !== -1) {
      this.tabs[tabIndex].url = formattedUrl;
      this.updateAddressBar();
    }
    try {
      await window.electronAPI.invoke('navigate-tab', { tabId: this.currentTabId, url: formattedUrl });
    } catch (e) {
      console.error('导航失败:', e);
    }
  }

  navigateFromAddressBar() {
    const urlInput = document.getElementById('url-input');
    const url = urlInput.value.trim();
    if (url) this.navigateCurrentTab(url);
  }

  formatUrl(input) {
    try {
      const urlObj = new URL(input);
      if (ALLOWED_PROTOCOLS.has(urlObj.protocol)) return input;
    } catch {}

    if (input.includes('.') && !input.includes(' ')) return 'https://' + input;

    const bang = resolveSearchBang(input);
    if (bang) return bang.url;

    const settings = getSettings();
    const searchEngine = settings.searchEngine || 'bing';
    let searchUrl;
    switch (searchEngine) {
      case 'google': searchUrl = 'https://www.google.com/search?q='; break;
      case 'baidu': searchUrl = 'https://www.baidu.com/s?wd='; break;
      case 'bing':
      default: searchUrl = 'https://www.bing.com/search?q='; break;
    }
    return searchUrl + encodeURIComponent(input);
  }

  async updateAddressBar() {
    if (!this.currentTabId) return;
    const currentTab = this.tabs.find(tab => tab.id === this.currentTabId);
    if (currentTab) {
      const urlInput = document.getElementById('url-input');
      if (urlInput) {
        urlInput.value = currentTab.url || '';
        this.updateSecurityBadge(currentTab.url);
      }
    }
  }

  updateSecurityBadge(url) {
    let badge = document.getElementById('security-badge');
    if (!badge) {
      badge = document.createElement('span');
      badge.id = 'security-badge';
      badge.className = 'security-badge';
      const urlInput = document.getElementById('url-input');
      if (urlInput && urlInput.parentNode) urlInput.parentNode.insertBefore(badge, urlInput);
    }
    try {
      const parsed = new URL(url);
      if (parsed.protocol === 'https:') {
        badge.textContent = '🔒';
        badge.className = 'security-badge secure';
      } else if (parsed.protocol === 'http:') {
        badge.textContent = '⚠';
        badge.className = 'security-badge insecure';
      } else {
        badge.textContent = '';
        badge.className = 'security-badge';
      }
    } catch {
      badge.textContent = '';
      badge.className = 'security-badge';
    }
  }

  async goBack() {
    try {
      await window.electronAPI.invoke('navigate-back');
    } catch (e) {
      console.error('后退失败:', e);
    }
  }

  async goForward() {
    try {
      await window.electronAPI.invoke('navigate-forward');
    } catch (e) {
      console.error('前进失败:', e);
    }
  }

  async refresh() {
    if (this.currentTabId) {
      const currentTab = this.tabs.find(tab => tab.id === this.currentTabId);
      if (currentTab) await this.navigateCurrentTab(currentTab.url);
    }
  }

  focusAddressBar() {
    const urlInput = document.getElementById('url-input');
    if (urlInput) {
      urlInput.focus();
      urlInput.select();
    }
  }

  setupContextMenu() {
    document.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      const selection = window.getSelection();
      const selectedText = selection.toString().trim();
      let menuType = 'blank';
      if (selectedText) menuType = 'selection';
      window.electronAPI.send('show-context-menu', { menuType, selectedText });
    });
  }

  showMoreOptionsMenu(event) {
    window.electronAPI.send('show-more-options-menu', { x: event.clientX, y: event.clientY });
  }

  toggleTabBarCollapse() {
    const tabBar = document.querySelector('.tab-bar-vertical');
    const isCollapsed = tabBar.classList.contains('collapsed');
    if (isCollapsed) {
      tabBar.classList.remove('collapsed');
      document.getElementById('collapse-tabbar').title = '收缩标签页';
      window.electronAPI.send('toggle-tabbar-collapse', false);
    } else {
      tabBar.classList.add('collapsed');
      document.getElementById('collapse-tabbar').title = '展开标签页';
      window.electronAPI.send('toggle-tabbar-collapse', true);
    }
    this.updateTitlebarTitle();
  }

  updateTitlebarTitle() {
    const titlebarTitle = document.getElementById('titlebar-title');
    if (!titlebarTitle) return;
    const tabBar = document.querySelector('.tab-bar-vertical');
    const isCollapsed = tabBar && tabBar.classList.contains('collapsed');
    if (isCollapsed && this.currentTabId) {
      const currentTab = this.tabs.find(tab => tab.id === this.currentTabId);
      titlebarTitle.textContent = (currentTab && currentTab.title) ? currentTab.title : 'OpenCosy浏览器';
    } else {
      titlebarTitle.textContent = (typeof COSY_CONSTANTS !== 'undefined' && COSY_CONSTANTS.APP_INFO) ? COSY_CONSTANTS.APP_INFO.name : 'OpenCosy浏览器';
    }
  }
}

const tabManager = new TabManager();

// ===== 快捷键帮助浮层（F1 / Ctrl+/）=====
const SHORTCUT_GROUPS = [
  { title: '标签页', items: [
    ['Ctrl + T', '新建标签页'], ['Ctrl + W', '关闭当前标签页'],
    ['Ctrl + Shift + T', '恢复最近关闭的标签页'], ['Ctrl + Tab', '下一个标签页'],
    ['Ctrl + Shift + Tab', '上一个标签页'], ['Ctrl + 1~8', '切换到第 N 个标签页'],
    ['Ctrl + 9', '切换到最后一个标签页'], ['Ctrl + Shift + 向右', '复制当前标签页'],
  ]},
  { title: '导航与编辑', items: [
    ['Alt + ←', '后退'], ['Alt + →', '前进'], ['F5 / Ctrl + R', '刷新'],
    ['Ctrl + Shift + R', '强制刷新（忽略缓存）'], ['Esc', '停止加载'],
    ['Ctrl + L', '聚焦地址栏'], ['Ctrl + K', '地址栏搜索'],
  ]},
  { title: '查找与缩放', items: [
    ['Ctrl + F', '在页面中查找'], ['Ctrl + G', '下一个匹配'],
    ['Ctrl + Shift + G', '上一个匹配'], ['Ctrl + +', '放大'],
    ['Ctrl + -', '缩小'], ['Ctrl + 0', '重置缩放'],
  ]},
  { title: '收藏与数据', items: [
    ['Ctrl + D', '收藏当前页'], ['Ctrl + Shift + D', '全部标签页收藏'],
    ['Ctrl + H', '历史记录'], ['Ctrl + J', '下载内容'],
    ['Ctrl + Shift + Del', '清除浏览数据'],
  ]},
  { title: '其他', items: [
    ['Ctrl + P', '打印'], ['F11', '全屏切换'], ['F1 / Ctrl + /', '显示本帮助'],
    ['Ctrl + Shift + B', '书签栏开关'],
  ]},
];

function buildShortcutsOverlay() {
  let overlay = document.getElementById('cosy-shortcuts-overlay');
  if (overlay) { overlay.remove(); return; }
  overlay = document.createElement('div');
  overlay.id = 'cosy-shortcuts-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:9999;display:flex;align-items:center;justify-content:center;';
  const panel = document.createElement('div');
  panel.style.cssText = 'background:var(--bg,#fff);color:var(--fg,#222);border-radius:12px;padding:20px 24px;max-width:680px;max-height:80vh;overflow:auto;box-shadow:0 12px 40px rgba(0,0,0,.3);font:13px/1.6 system-ui,sans-serif;';
  panel.innerHTML = '<h2 style="margin:0 0 12px;font-size:18px;">键盘快捷键</h2>';
  SHORTCUT_GROUPS.forEach(g => {
    const h = document.createElement('div');
    h.style.cssText = 'font-weight:600;margin:12px 0 6px;color:#4a90e2;';
    h.textContent = g.title;
    panel.appendChild(h);
    const grid = document.createElement('div');
    grid.style.cssText = 'display:grid;grid-template-columns:auto 1fr;gap:4px 16px;';
    g.items.forEach(([k, desc]) => {
      const kEl = document.createElement('kbd');
      kEl.style.cssText = 'background:#f0f0f0;border:1px solid #ccc;border-radius:4px;padding:1px 6px;font-family:monospace;font-size:12px;white-space:nowrap;';
      kEl.textContent = k;
      const dEl = document.createElement('span');
      dEl.textContent = desc;
      grid.appendChild(kEl);
      grid.appendChild(dEl);
    });
    panel.appendChild(grid);
  });
  const closeBtn = document.createElement('div');
  closeBtn.style.cssText = 'margin-top:16px;text-align:center;color:#888;font-size:12px;';
  closeBtn.textContent = '按 Esc 或点击任意处关闭';
  panel.appendChild(closeBtn);
  overlay.appendChild(panel);
  overlay.addEventListener('click', () => overlay.remove());
  document.body.appendChild(overlay);
}

document.addEventListener('keydown', (e) => {
  if (e.key === 'F1' || (e.ctrlKey && e.key === '/')) {
    e.preventDefault();
    buildShortcutsOverlay();
  } else if (e.key === 'Escape') {
    const ov = document.getElementById('cosy-shortcuts-overlay');
    if (ov) ov.remove();
  }
});

// ===== 网络状态提示（online / offline pill）=====
function ensureNetworkPill() {
  let pill = document.getElementById('cosy-net-pill');
  if (pill) return pill;
  pill = document.createElement('div');
  pill.id = 'cosy-net-pill';
  pill.style.cssText = 'position:fixed;bottom:12px;left:50%;transform:translateX(-50%);padding:6px 14px;border-radius:16px;font:12px/1 system-ui,sans-serif;z-index:9998;box-shadow:0 2px 8px rgba(0,0,0,.2);transition:opacity .3s;opacity:0;';
  document.body.appendChild(pill);
  return pill;
}

function showNetworkPill(text, bg) {
  const pill = ensureNetworkPill();
  pill.textContent = text;
  pill.style.background = bg;
  pill.style.color = '#fff';
  pill.style.opacity = '1';
  clearTimeout(pill._timer);
  pill._timer = setTimeout(() => { pill.style.opacity = '0'; }, 3000);
}

window.addEventListener('online', () => showNetworkPill('已恢复网络连接', '#2e7d32'));
window.addEventListener('offline', () => showNetworkPill('网络已断开，浏览器将以离线模式运行', '#c62828'));
if (!navigator.onLine) {
  document.addEventListener('DOMContentLoaded', () => showNetworkPill('当前处于离线状态', '#c62828'));
}

// ===== 渲染进程崩溃 / 无响应信息条（Chrome 风格横幅）=====
const RECOVERY_REASON_TEXT = {
  crashed: '崩溃',
  oom: '内存不足（OOM）',
  killed: '进程被系统终止',
  'abnormal-exit': '异常退出',
  'launch-failed': '启动失败',
  unknown: '发生未知错误',
};

function hideRecoveryInfobar() {
  const bar = document.getElementById('cosy-recovery-bar');
  if (bar) bar.remove();
}

function recoveryActionButton(label, primary, onClick) {
  const b = document.createElement('button');
  b.textContent = label;
  b.style.cssText = 'margin-left:8px;padding:4px 12px;border:none;border-radius:4px;font:12px/1.4 system-ui,sans-serif;cursor:pointer;' +
    (primary ? 'background:#1a73e8;color:#fff;' : 'background:transparent;color:#1a73e8;border:1px solid #1a73e8;');
  b.addEventListener('click', () => { onClick(); hideRecoveryInfobar(); });
  return b;
}

function showRecoveryBar(message, actions) {
  hideRecoveryInfobar();
  const bar = document.createElement('div');
  bar.id = 'cosy-recovery-bar';
  bar.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:10000;display:flex;align-items:center;gap:6px;padding:8px 16px;background:#fce8e6;color:#3c4043;font:13px/1.5 system-ui,sans-serif;box-shadow:0 1px 4px rgba(0,0,0,.18);';
  const span = document.createElement('span');
  span.textContent = message;
  span.style.flex = '1';
  bar.appendChild(span);
  actions.forEach(a => bar.appendChild(recoveryActionButton(a.label, !!a.primary, a.onClick)));
  document.body.appendChild(bar);
}

function showCrashInfobar(data) {
  const reasonText = RECOVERY_REASON_TEXT[data.reason] || RECOVERY_REASON_TEXT.unknown;
  const tabId = data.tabId;
  const url = typeof data.url === 'string' ? data.url : '';
  const reload = () => window.electronAPI.send('reload-tab-by-id', tabId);
  const reopen = () => window.electronAPI.send('reopen-tab-url', url);
  if (data.autoReloaded) {
    showRecoveryBar(`此页面因${reasonText}崩溃，正在自动重新加载…`, [
      { label: '立即刷新', primary: true, onClick: reload },
    ]);
    return;
  }
  const actions = [{ label: '重新加载', primary: true, onClick: reload }];
  if (/^https?:/i.test(url)) actions.push({ label: '在新标签页重新打开', onClick: reopen });
  showRecoveryBar(`此页面的渲染进程因${reasonText}已停止。${data.exitCode != null ? `（退出码 ${data.exitCode}）` : ''}`, actions);
}

function showUnresponsiveInfobar(data) {
  // 无响应可能只是暂时卡顿，不立刻覆盖已有的崩溃横幅。
  if (document.getElementById('cosy-recovery-bar')) return;
  const tabId = data && data.tabId;
  showRecoveryBar('此页面无响应。可以继续等待，也可以强制刷新。', [
    { label: '强制刷新', primary: true, onClick: () => window.electronAPI.send('reload-tab-by-id', tabId) },
  ]);
}

// ===== 同形异义 / IDN 反钓鱼提示条（琥珀色，仅提醒不阻断）=====
const SPOOF_REASON_TEXT = {
  'mixed-script': '网址混合了不同字母体系（如拉丁字母与西里尔字母），可能在仿冒常见网站',
  'digit-lookalike': '网址用数字替代了品牌名中的字母，可能是仿冒网站',
};

function showSpoofWarning(data) {
  if (!data || !data.hostname) return;
  // 同一主机一次会话只提醒一次，避免每次子资源/刷新都弹。
  if (!showSpoofWarning._seen) showSpoofWarning._seen = new Set();
  if (showSpoofWarning._seen.has(data.hostname)) return;
  showSpoofWarning._seen.add(data.hostname);

  let bar = document.getElementById('cosy-spoof-bar');
  if (!bar) {
    bar = document.createElement('div');
    bar.id = 'cosy-spoof-bar';
    bar.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:10001;display:flex;align-items:center;gap:8px;padding:9px 16px;background:#fef7e0;color:#5f4700;font:13px/1.5 system-ui,sans-serif;box-shadow:0 1px 4px rgba(0,0,0,.18);';
    document.body.appendChild(bar);
  }
  bar.textContent = '';
  const icon = document.createElement('span');
  icon.textContent = '⚠';
  const msg = document.createElement('span');
  msg.style.flex = '1';
  msg.textContent = `${SPOOF_REASON_TEXT[data.reason] || '该网址含有易混淆字符'}：${data.hostname}。请核对地址栏，勿在此页面输入账号密码或付款信息。`;
  const close = document.createElement('button');
  close.textContent = '知道了';
  close.style.cssText = 'border:1px solid #b08400;background:transparent;color:#5f4700;border-radius:4px;padding:4px 12px;font:12px/1.4 system-ui,sans-serif;cursor:pointer;';
  close.addEventListener('click', () => bar.remove());
  bar.appendChild(icon);
  bar.appendChild(msg);
  bar.appendChild(close);
}

// ===== 追踪拦截盾牌（右下角计数，点击查看 / 归零）=====
let trackerSnapshot = { enabled: true, count: 0, top: [] };

function ensureTrackerShield() {
  let el = document.getElementById('cosy-tracker-shield');
  if (el) return el;
  el = document.createElement('div');
  el.id = 'cosy-tracker-shield';
  el.style.cssText = 'position:fixed;right:14px;bottom:14px;z-index:9997;display:none;align-items:center;gap:6px;padding:6px 12px;border-radius:18px;background:rgba(26,115,232,.92);color:#fff;font:12px/1 system-ui,sans-serif;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,.25);user-select:none;';
  const icon = document.createElement('span');
  icon.textContent = '🛡';
  const num = document.createElement('span');
  num.id = 'cosy-tracker-num';
  num.textContent = '0';
  el.appendChild(icon);
  el.appendChild(num);
  el.addEventListener('click', openTrackerReport);
  document.body.appendChild(el);
  return el;
}

function updateTrackerShield(data) {
  if (!data || data.enabled === false) return;
  trackerSnapshot = {
    enabled: true,
    count: data.count || 0,
    top: Array.isArray(data.top) ? data.top : [],
  };
  const el = ensureTrackerShield();
  const num = document.getElementById('cosy-tracker-num');
  if (num) num.textContent = String(trackerSnapshot.count);
  el.style.display = (trackerSnapshot.count > 0) ? 'flex' : 'none';
  const panel = document.getElementById('cosy-tracker-list');
  if (panel) renderTrackerList(panel); // 弹窗开着时实时刷新
}

function renderTrackerList(container) {
  container.textContent = '';
  if (!trackerSnapshot.top.length) {
    const empty = document.createElement('div');
    empty.textContent = '本次还没有拦截到追踪请求';
    empty.style.cssText = 'padding:18px;text-align:center;color:#888;font-size:13px;';
    container.appendChild(empty);
    return;
  }
  for (const item of trackerSnapshot.top) {
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;justify-content:space-between;align-items:center;padding:8px 4px;border-bottom:1px solid #f0f0f0;font-size:13px;';
    const host = document.createElement('span');
    host.textContent = item.host;
    host.style.cssText = 'color:#333;word-break:break-all;';
    const n = document.createElement('span');
    n.textContent = String(item.n);
    n.style.cssText = 'margin-left:12px;color:#1a73e8;font-variant-numeric:tabular-nums;flex:none;';
    row.appendChild(host);
    row.appendChild(n);
    container.appendChild(row);
  }
}

function openTrackerReport() {
  let ov = document.getElementById('cosy-tracker-report');
  if (ov) { ov.remove(); return; }
  ov = document.createElement('div');
  ov.id = 'cosy-tracker-report';
  ov.style.cssText = 'position:fixed;inset:0;z-index:10001;background:rgba(0,0,0,.4);display:flex;align-items:center;justify-content:center;';
  ov.addEventListener('click', e => { if (e.target === ov) ov.remove(); });

  const panel = document.createElement('div');
  panel.style.cssText = 'width:420px;max-width:92vw;background:#fff;border-radius:12px;box-shadow:0 12px 40px rgba(0,0,0,.3);overflow:hidden;font:13px/1.5 system-ui,sans-serif;';

  const head = document.createElement('div');
  head.style.cssText = 'display:flex;align-items:center;justify-content:space-between;padding:16px 18px;border-bottom:1px solid #eee;';
  const title = document.createElement('strong');
  title.textContent = '🛡 追踪拦截';
  title.style.cssText = 'font-size:15px;color:#222;';
  const closeX = document.createElement('button');
  closeX.textContent = '×';
  closeX.style.cssText = 'border:none;background:none;font-size:20px;line-height:1;color:#888;cursor:pointer;';
  closeX.addEventListener('click', () => ov.remove());
  head.appendChild(title);
  head.appendChild(closeX);

  const summary = document.createElement('div');
  summary.style.cssText = 'padding:14px 18px;background:#f6f9ff;color:#1a73e8;font-size:14px;';
  const strong = document.createElement('strong');
  strong.textContent = String(trackerSnapshot.count);
  strong.style.cssText = 'font-size:22px;margin-right:6px;';
  summary.appendChild(strong);
  summary.appendChild(document.createTextNode('个追踪请求已在本次浏览中被拦截'));

  const list = document.createElement('div');
  list.id = 'cosy-tracker-list';
  list.style.cssText = 'max-height:40vh;overflow:auto;padding:4px 18px;';
  renderTrackerList(list);

  const foot = document.createElement('div');
  foot.style.cssText = 'display:flex;justify-content:flex-end;gap:10px;padding:12px 18px;border-top:1px solid #eee;';
  const tip = document.createElement('span');
  tip.textContent = '仅统计当前会话，可在设置中关闭拦截';
  tip.style.cssText = 'flex:1;color:#999;font-size:12px;align-self:center;';
  const resetBtn = document.createElement('button');
  resetBtn.textContent = '清零计数';
  resetBtn.style.cssText = 'padding:6px 14px;border:1px solid #ddd;border-radius:6px;background:#fff;color:#444;cursor:pointer;font-size:13px;';
  resetBtn.addEventListener('click', () => {
    window.electronAPI.send('reset-trackers');
    updateTrackerShield({ enabled: true, count: 0, top: [] });
  });
  foot.appendChild(tip);
  foot.appendChild(resetBtn);

  panel.appendChild(head);
  panel.appendChild(summary);
  panel.appendChild(list);
  panel.appendChild(foot);
  ov.appendChild(panel);
  document.body.appendChild(ov);
}


// 主界面（可能晚于主进程计数）加载后拉取一次当前拦截状态。
document.addEventListener('DOMContentLoaded', () => {
  if (!window.electronAPI || !window.electronAPI.invoke) return;
  window.electronAPI.invoke('get-trackers')
    .then(r => { if (r && r.success) updateTrackerShield({ enabled: r.enabled, count: r.count, top: r.top }); })
    .catch(() => {});
});

// ===== 标签页切换器（Ctrl+Shift+A）=====
function openTabSwitcher() {
  let ov = document.getElementById('cosy-tab-switcher');
  if (ov) { ov.remove(); return; }
  ov = document.createElement('div');
  ov.id = 'cosy-tab-switcher';
  ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:9999;display:flex;align-items:flex-start;justify-content:center;padding-top:15vh;';
  const panel = document.createElement('div');
  panel.style.cssText = 'background:#fff;border-radius:10px;width:560px;max-height:60vh;overflow:auto;box-shadow:0 12px 40px rgba(0,0,0,.3);font:13px/1.5 system-ui,sans-serif;';
  const inp = document.createElement('input');
  inp.placeholder = '筛选标签页...';
  inp.style.cssText = 'width:100%;box-sizing:border-box;padding:10px 14px;border:none;border-bottom:1px solid #eee;outline:none;font-size:14px;';
  panel.appendChild(inp);
  const list = document.createElement('div');
  list.style.cssText = 'padding:6px 0;';
  function render(filter) {
    list.innerHTML = '';
    tabManager.tabs
      .filter(t => !filter || (t.title && t.title.toLowerCase().includes(filter)) || (t.url && t.url.toLowerCase().includes(filter)))
      .forEach(t => {
        const row = document.createElement('div');
        row.style.cssText = 'padding:8px 14px;cursor:pointer;display:flex;flex-direction:column;' + (t.id === tabManager.currentTabId ? 'background:#e8f0fe;' : '');
        const title = document.createElement('div');
        title.style.cssText = 'font-weight:600;color:#222;';
        title.textContent = t.title || t.url || '(无标题)';
        const url = document.createElement('div');
        url.style.cssText = 'font-size:11px;color:#888;';
        url.textContent = t.url || '';
        row.appendChild(title); row.appendChild(url);
        row.addEventListener('click', () => { ov.remove(); tabManager.switchToTab(t.id); });
        list.appendChild(row);
      });
  }
  render('');
  inp.addEventListener('input', () => render(inp.value.trim().toLowerCase()));
  inp.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') ov.remove();
    if (e.key === 'Enter') {
      const first = list.querySelector('div');
      if (first) first.click();
    }
  });
  panel.appendChild(list);
  ov.appendChild(panel);
  ov.addEventListener('click', (e) => { if (e.target === ov) ov.remove(); });
  document.body.appendChild(ov);
  inp.focus();
}

document.addEventListener('keydown', (e) => {
  if (e.ctrlKey && e.shiftKey && (e.key === 'A' || e.key === 'a')) {
    e.preventDefault();
    openTabSwitcher();
  }
});

// ===== 阅读模式（Ctrl+Shift+R）：注入简化 CSS =====
let readerStyleEl = null;
function toggleReaderMode() {
  if (readerStyleEl) {
    readerStyleEl.remove();
    readerStyleEl = null;
    return;
  }
  const css = `
    body { max-width: 720px !important; margin: 0 auto !important;
      font-family: system-ui, sans-serif !important; line-height: 1.7 !important;
      color: #222 !important; background: #faf8f2 !important; }
    nav, header, footer, aside, .ad, .advertisement, [class*="banner"], [id*="banner"],
    [class*="sidebar"], [id*="sidebar"], [class*="comment"], [id*="comment"] { display: none !important; }
    img, video { max-width: 100% !important; height: auto !important; }
    a { color: #1a73e8 !important; }
  `;
  readerStyleEl = document.createElement('style');
  readerStyleEl.id = 'cosy-reader-style';
  readerStyleEl.textContent = css;
  document.head.appendChild(readerStyleEl);
}
document.addEventListener('keydown', (e) => {
  if (e.ctrlKey && e.shiftKey && (e.key === 'R' || e.key === 'r')) {
    e.preventDefault();
    toggleReaderMode();
  }
});

// ===== 常驻书签栏（Ctrl+Shift+B 切换）=====
function renderPersistentBookmarksBar() {
  let bar = document.getElementById('cosy-persist-bookmarks');
  const show = localStorage.getItem('cosyShowBookmarksBar') === '1';
  if (!show) { if (bar) bar.remove(); return; }
  if (!bar) {
    bar = document.createElement('div');
    bar.id = 'cosy-persist-bookmarks';
    bar.style.cssText = 'display:flex;align-items:center;gap:4px;padding:4px 8px;background:#f3f3f3;border-bottom:1px solid #ddd;overflow-x:auto;font:12px/1.4 system-ui,sans-serif;';
    document.body.insertBefore(bar, document.body.firstChild);
  }
  bar.innerHTML = '';
  (typeof tabManager !== 'undefined' ? tabManager.bookmarks : []).forEach(b => {
    const chip = document.createElement('div');
    chip.style.cssText = 'padding:3px 10px;border-radius:4px;background:#fff;border:1px solid #ddd;cursor:pointer;white-space:nowrap;';
    chip.textContent = b.title || b.url;
    chip.title = b.url;
    chip.addEventListener('click', () => tabManager.createNewTab(b.url));
    bar.appendChild(chip);
  });
  if (bar.children.length === 0) {
    bar.innerHTML = '<span style="color:#888;padding:0 8px;">暂无书签 · Ctrl+D 添加</span>';
  }
}

document.addEventListener('keydown', (e) => {
  if (e.ctrlKey && e.shiftKey && (e.key === 'B' || e.key === 'b')) {
    e.preventDefault();
    const cur = localStorage.getItem('cosyShowBookmarksBar') === '1';
    localStorage.setItem('cosyShowBookmarksBar', cur ? '0' : '1');
    renderPersistentBookmarksBar();
  }
});

document.addEventListener('DOMContentLoaded', renderPersistentBookmarksBar);
if (window.electronAPI) {
  window.electronAPI.on('bookmarks-updated', () => {
    if (typeof tabManager !== 'undefined') renderPersistentBookmarksBar();
  });
}

// ===== 查看网页源代码（Ctrl+U）=====
document.addEventListener('keydown', (e) => {
  if (e.ctrlKey && (e.key === 'u' || e.key === 'U')) {
    e.preventDefault();
    if (typeof tabManager !== 'undefined' && tabManager.currentTabId) {
      const t = tabManager.tabs.find(x => x.id === tabManager.currentTabId);
      if (t && t.url && /^https?:/i.test(t.url)) {
        tabManager.createNewTab('view-source:' + t.url);
      }
    }
  }
});

// ===== 地址栏自动补全（历史/书签 + 远程搜索建议，支持方向键选择）=====
function setupOmniboxAutocomplete() {
  const input = document.getElementById('url-input');
  if (!input || input._autocompleteAttached) return;
  input._autocompleteAttached = true;
  let drop = document.getElementById('omnibox-dropdown');
  if (!drop) {
    drop = document.createElement('div');
    drop.id = 'omnibox-dropdown';
    drop.style.cssText = 'position:absolute;top:100%;left:0;right:0;background:#fff;border:1px solid #ddd;border-top:none;max-height:320px;overflow-y:auto;z-index:999;display:none;box-shadow:0 8px 20px rgba(0,0,0,.15);font:13px/1.4 system-ui,sans-serif;';
    input.parentElement.style.position = 'relative';
    input.parentElement.appendChild(drop);
  }

  // rows 保存当前下拉里每一项；value 是选中后要写进地址栏/用于导航的内容。
  let rows = [];
  let active = -1;
  let debounceTimer = null;
  let reqSeq = 0;

  function close() {
    drop.style.display = 'none';
    rows = [];
    active = -1;
  }

  function localMatches(q) {
    const out = [];
    const seen = new Set();
    const pool = [
      ...((tabManager.bookmarks) || []).map(b => ({ title: b.title, url: b.url, tag: '书签' })),
      ...((tabManager.history) || []).map(h => ({ title: h.title || h.url, url: h.url, tag: '历史' })),
    ];
    for (const item of pool) {
      if (seen.has(item.url)) continue;
      if (item.url.toLowerCase().includes(q) || (item.title || '').toLowerCase().includes(q)) {
        out.push({ title: item.title || item.url, value: item.url, tag: item.tag });
        seen.add(item.url);
      }
      if (out.length >= 6) break;
    }
    return out;
  }

  function draw() {
    if (rows.length === 0) { close(); return; }
    drop.innerHTML = '';
    rows.forEach((m, i) => {
      const row = document.createElement('div');
      row.dataset.idx = i;
      row.style.cssText = 'padding:8px 12px;cursor:pointer;display:flex;flex-direction:column;' +
        (i === active ? 'background:#e8f0fe;' : '');
      row.innerHTML = `<strong style="color:#222;font-weight:600;">${escapeHtml(m.title || m.value)}</strong>` +
        `<span style="color:#888;font-size:11px;">${escapeHtml(m.tag === '搜索建议' ? m.value : m.value)} · ${m.tag}</span>`;
      row.addEventListener('mousedown', (e) => {
        e.preventDefault();
        input.value = m.value;
        close();
        tabManager.navigateFromAddressBar();
      });
      row.addEventListener('mouseenter', () => setActive(i));
      drop.appendChild(row);
    });
    drop.style.display = 'block';
  }

  function setActive(i) {
    if (rows.length === 0) return;
    active = (i + rows.length) % rows.length;
    input.value = rows[active].value;
    Array.from(drop.children).forEach((el, idx) => {
      el.style.background = idx === active ? '#e8f0fe' : '';
    });
    const cur = drop.children[active];
    if (cur && cur.scrollIntoView) cur.scrollIntoView({ block: 'nearest' });
  }

  async function refresh() {
    const q = input.value.trim().toLowerCase();
    if (!q || typeof tabManager === 'undefined') { close(); return; }
    const seq = ++reqSeq;
    const base = localMatches(q);
    let remote = [];
    try {
      // 纯 URL / 内置协议不发搜索请求，避免把完整地址泄漏给搜索引擎。
      if (!/^[a-z][a-z0-9+.-]*:/i.test(q) && !q.startsWith('//')) {
        const r = await window.electronAPI.invoke('get-search-suggestions', { q: input.value.trim() });
        if (seq === reqSeq && r && r.success && Array.isArray(r.suggestions)) {
          const exist = new Set(base.map(b => b.value.toLowerCase()));
          remote = r.suggestions
            .filter(s => !exist.has(s.toLowerCase()))
            .slice(0, 6)
            .map(s => ({ title: s, value: s, tag: '搜索建议' }));
        }
      }
    } catch {}
    if (seq !== reqSeq) return; // 已有更新的输入，丢弃过期响应
    rows = base.concat(remote).slice(0, 10);
    active = -1;
    draw();
  }

  input.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(refresh, 150);
  });
  input.addEventListener('keydown', (e) => {
    if (drop.style.display !== 'block') {
      if (e.key === 'Escape') close();
      return;
    }
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive(active + 1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive(active - 1); }
    else if (e.key === 'Escape') { e.preventDefault(); close(); }
    else if (e.key === 'Enter' && active >= 0) {
      // 选中项的值在方向键选择时已写进输入框，这里只关下拉，
      // 导航交给地址栏既有的 Enter 处理，避免重复触发。
      close();
    }
  });
  input.addEventListener('blur', () => setTimeout(close, 150));
  input.addEventListener('focus', refresh);
}
document.addEventListener('DOMContentLoaded', setupOmniboxAutocomplete);

// ===== 暗色模式切换（Ctrl+Shift+D）=====
function applyDarkMode(on) {
  document.documentElement.style.filter = on ? 'invert(0.92) hue-rotate(180deg)' : '';
  localStorage.setItem('cosyDark', on ? '1' : '0');
}
applyDarkMode(localStorage.getItem('cosyDark') === '1');
document.addEventListener('keydown', (e) => {
  if (e.ctrlKey && e.shiftKey && (e.key === 'D' || e.key === 'd')) {
    e.preventDefault();
    applyDarkMode(localStorage.getItem('cosyDark') !== '1');
  }
});

// ===== 快速清空浏览数据（Ctrl+Shift+Delete）=====
document.addEventListener('keydown', (e) => {
  if (e.ctrlKey && e.shiftKey && (e.key === 'Delete' || e.key === 'Backspace')) {
    e.preventDefault();
    if (confirm('确定清除所有浏览数据（缓存 / Cookie / 历史）？')) {
      window.electronAPI.send('clear-browsing-data');
    }
  }
});

// ===== 历史记录面板（Ctrl+H）=====
function openHistoryPanel() {
  let ov = document.getElementById('cosy-history-panel');
  if (ov) { ov.remove(); return; }
  ov = document.createElement('div');
  ov.id = 'cosy-history-panel';
  ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:9999;display:flex;align-items:flex-start;justify-content:center;padding-top:10vh;';
  const panel = document.createElement('div');
  panel.style.cssText = 'background:#fff;border-radius:10px;width:560px;max-height:70vh;overflow:auto;box-shadow:0 12px 40px rgba(0,0,0,.3);font:13px/1.5 system-ui,sans-serif;';
  panel.innerHTML = '<h3 style="margin:0;padding:14px 16px;border-bottom:1px solid #eee;">最近访问</h3>';
  const list = document.createElement('div');
  list.style.cssText = 'padding:6px 0;';
  (typeof tabManager !== 'undefined' ? tabManager.history.slice(-50).reverse() : []).forEach(h => {
    const row = document.createElement('div');
    row.style.cssText = 'padding:8px 16px;cursor:pointer;';
    row.innerHTML = `<strong style="color:#222;">${escapeHtml(h.title || h.url)}</strong><br><span style="color:#888;font-size:11px;">${escapeHtml(h.url)}</span>`;
    row.addEventListener('click', () => { ov.remove(); tabManager.createNewTab(h.url); });
    list.appendChild(row);
  });
  if (list.children.length === 0) list.innerHTML = '<div style="padding:20px;color:#888;text-align:center;">暂无历史记录</div>';
  panel.appendChild(list);
  ov.appendChild(panel);
  ov.addEventListener('click', (e) => { if (e.target === ov) ov.remove(); });
  document.body.appendChild(ov);
}
document.addEventListener('keydown', (e) => {
  if (e.ctrlKey && (e.key === 'h' || e.key === 'H')) {
    e.preventDefault();
    openHistoryPanel();
  }
});

// 标签页右键菜单统一由下方 setupTabExtras 的 cosy-tab-ctx2 提供。
// 早期绑定 #tab-strip / dataset.id 的旧菜单已删除：该 DOM 结构不存在，
// 旧函数拿到 null 后直接返回，属于永不生效的死代码。

// ===== 会话恢复：退出前保存标签，下次启动自动还原 =====
(function setupSessionRestore() {
  const KEY = 'cosySession';
  function snapshot() {
    try {
      if (typeof tabManager === 'undefined' || !tabManager.tabs) return;
      const urls = tabManager.tabs.map(t => t.url).filter(u => u && isSafeUrl(u));
      if (urls.length === 0) return;
      const active = tabManager.tabs.findIndex(t => t.id === tabManager.currentTabId);
      localStorage.setItem(KEY, JSON.stringify({ urls, active: active < 0 ? 0 : active, ts: Date.now() }));
    } catch (e) { /* 忽略存储异常 */ }
  }
  setInterval(snapshot, 1500);
  window.addEventListener('beforeunload', snapshot);

  async function restore() {
    let data;
    try { data = JSON.parse(localStorage.getItem(KEY) || 'null'); } catch { return; }
    if (!data || !Array.isArray(data.urls) || data.urls.length === 0) return;
    // 启动时主进程自动开的空白新标签页，记录下来稍后关掉
    const defaultTabIds = (tabManager.tabs || [])
      .filter(t => !t.url || t.url === 'cosy://newtab')
      .map(t => t.id);
    let firstId = null;
    for (const url of data.urls) {
      const id = await tabManager.createNewTab(url);
      if (!firstId && id) firstId = id;
    }
    // 等 IPC 把新标签状态同步回来再关默认标签
    setTimeout(() => {
      const stillDefault = (tabManager.tabs || [])
        .filter(t => defaultTabIds.includes(t.id) && (!t.url || t.url === 'cosy://newtab'));
      stillDefault.forEach((t, i) => { if (i < defaultTabIds.length) tabManager.closeTab(t.id); });
    }, 400);
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => setTimeout(restore, 300));
  } else {
    setTimeout(restore, 300);
  }
})();

// reopenClosedTab 恢复最近关闭的标签页。
// 主进程在关闭时把 URL 压入 recentlyClosedTabs，这里通过 IPC 取出并新开。
// 没有可恢复项时给一个轻提示，不报错。
async function reopenClosedTab() {
  try {
    const res = await window.electronAPI.invoke('reopen-closed-tab');
    if (!res || !res.success) {
      if (typeof tabManager !== 'undefined' && tabManager.showToast) tabManager.showToast('没有可恢复的标签页');
    }
  } catch { /* 主进程不可用时静默 */ }
}

document.addEventListener('keydown', (e) => {
  if (e.ctrlKey && e.shiftKey && (e.key === 'T' || e.key === 't')) {
    e.preventDefault();
    reopenClosedTab();
  }
});

// ===== 标签交互增强：修正右键菜单目标 + 中键关闭 + Ctrl+Enter .com + 复制标签 =====
(function setupTabExtras() {
  let menu = null;
  function buildMenu(x, y, tabId) {
    if (!menu) {
      menu = document.createElement('div');
      menu.id = 'cosy-tab-ctx2';
      menu.style.cssText = 'position:fixed;background:#fff;border:1px solid #ddd;border-radius:6px;box-shadow:0 6px 20px rgba(0,0,0,.18);z-index:10001;display:none;min-width:180px;font:13px/1.4 system-ui,sans-serif;';
      document.body.appendChild(menu);
    }
    menu.innerHTML = '';
    const items = [
      { label: '重新加载', fn: () => tabManager.reloadTab(tabId) },
      { label: '复制标签页', fn: () => {
          const t = tabManager.tabs.find(t => t.id === tabId);
          if (t && t.url) tabManager.createNewTab(t.url);
        } },
      { label: '复制网址', fn: () => {
          const t = tabManager.tabs.find(t => t.id === tabId);
          if (t) navigator.clipboard.writeText(t.url || '');
        } },
      { label: '重新打开关闭的标签页', fn: reopenClosedTab },
      { divider: true },
      { label: '休眠此标签页（释放内存）',
        fn: () => window.electronAPI.invoke('discard-tab', { tabId }) },
      { label: '休眠所有后台标签页',
        fn: () => window.electronAPI.invoke('discard-background-tabs').then(r => {
          const n = (r && r.count) || 0;
          tabManager.showToast(n > 0 ? `已休眠 ${n} 个后台标签页` : '没有需要休眠的后台标签页');
        }) },
      { divider: true },
      { label: tabManager.tabs.find(t => t.id === tabId && t.muted) ? '取消静音标签页' : '静音标签页',
        fn: () => {
          const t = tabManager.tabs.find(t => t.id === tabId);
          window.electronAPI.invoke('set-tab-muted', { tabId, muted: !(t && t.muted) });
        } },
      { divider: true },
      { label: '关闭标签页', fn: () => tabManager.closeTab(tabId) },
      { label: '关闭左侧标签页', fn: () => {
          const order = tabManager.tabs.map(t => t.id);
          const i = order.indexOf(tabId);
          if (i > 0) order.slice(0, i).forEach(id => tabManager.closeTab(id));
        } },
      { label: '关闭右侧标签页', fn: () => {
          const order = tabManager.tabs.map(t => t.id);
          const i = order.indexOf(tabId);
          if (i >= 0) order.slice(i + 1).forEach(id => tabManager.closeTab(id));
        } },
      { label: '关闭其他标签页', fn: () => tabManager.tabs.filter(t => t.id !== tabId).forEach(t => tabManager.closeTab(t.id)) },
      { label: '重新加载所有标签页', fn: () => tabManager.tabs.forEach(t => tabManager.reloadTab(t.id)) },
      { divider: true },
      { label: '静音其他标签页', fn: () => {
          tabManager.tabs.filter(t => t.id !== tabId).forEach(t => {
            if (!t.muted) window.electronAPI.invoke('set-tab-muted', { tabId: t.id, muted: true });
          });
        } },
    ];
    items.forEach(it => {
      if (it.divider) {
        const sep = document.createElement('div');
        sep.style.cssText = 'height:1px;margin:4px 8px;background:rgba(0,0,0,0.12);';
        menu.appendChild(sep);
        return;
      }
      const row = document.createElement('div');
      row.textContent = it.label;
      row.style.cssText = 'padding:8px 14px;cursor:pointer;';
      row.addEventListener('mouseenter', () => row.style.background = '#f0f0f0');
      row.addEventListener('mouseleave', () => row.style.background = '');
      row.addEventListener('click', () => { menu.style.display = 'none'; it.fn(); });
      menu.appendChild(row);
    });
    menu.style.left = x + 'px';
    menu.style.top = y + 'px';
    menu.style.display = 'block';
  }
  document.addEventListener('click', () => { if (menu) menu.style.display = 'none'; });

  function bindStrip() {
    const strip = document.getElementById('tabs-container');
    if (!strip || strip._extraAttached) return false;
    strip._extraAttached = true;
    strip.addEventListener('contextmenu', (e) => {
      const tabEl = e.target.closest('.tab');
      if (!tabEl) return;
      e.preventDefault();
      buildMenu(e.clientX, e.clientY, parseInt(tabEl.dataset.tabId));
    });
    // 中键点击标签直接关闭
    strip.addEventListener('mousedown', (e) => {
      if (e.button !== 1) return;
      const tabEl = e.target.closest('.tab');
      if (!tabEl) return;
      e.preventDefault();
      tabManager.closeTab(parseInt(tabEl.dataset.tabId));
    });
    return true;
  }

  // 地址栏 Ctrl+Enter：裸域名自动补 .com，含空格走搜索
  function bindOmnibox() {
    const input = document.getElementById('url-input');
    if (!input || input._comAttached) return;
    input._comAttached = true;
    input.addEventListener('keydown', (e) => {
      if (e.ctrlKey && e.key === 'Enter') {
        e.preventDefault();
        let v = input.value.trim();
        if (!v) return;
        if (v.includes(' ')) {
          input.value = 'https://www.bing.com/search?q=' + encodeURIComponent(v);
        } else if (!/^[a-z]+:/i.test(v) && !v.includes('.') && !v.startsWith('//')) {
          input.value = 'https://' + v + '.com';
        }
        tabManager.navigateFromAddressBar();
      }
    });
  }

  document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.shiftKey && (e.key === 'K' || e.key === 'k')) {
      e.preventDefault();
      const t = tabManager.tabs.find(t => t.id === tabManager.currentTabId);
      if (t && t.url) tabManager.createNewTab(t.url);
    }
  });

  function init() { bindStrip(); bindOmnibox(); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
  // 标签容器可能延迟渲染，再兜底一次
  setTimeout(init, 500);
})();

// ===== 键盘标签切换：Ctrl+Tab / Ctrl+Shift+Tab / Ctrl+1~9 =====
(function setupTabKeyboardNav() {
  function cycle(step) {
    const tabs = tabManager.tabs || [];
    if (tabs.length === 0) return;
    const idx = tabs.findIndex(t => t.id === tabManager.currentTabId);
    const n = tabs.length;
    const next = tabs[(idx + step + n) % n];
    if (next) tabManager.switchToTab(next.id);
  }
  document.addEventListener('keydown', (e) => {
    // Ctrl+Tab 下一个，Ctrl+Shift+Tab 上一个（部分系统拦截，再补 PgUp/PgDn）
    if (e.ctrlKey && (e.key === 'Tab' || e.key === 'PageDown')) {
      e.preventDefault();
      cycle(e.shiftKey ? -1 : 1);
      return;
    }
    if (e.ctrlKey && e.shiftKey && e.key === 'PageUp') {
      e.preventDefault();
      cycle(-1);
      return;
    }
    // Ctrl+1..8 切到第 N 个，Ctrl+9 切到最后一个
    if (e.ctrlKey && !e.altKey && !e.shiftKey && /^[1-9]$/.test(e.key)) {
      const tabs = tabManager.tabs || [];
      const n = parseInt(e.key, 10);
      const target = n === 9 ? tabs[tabs.length - 1] : tabs[n - 1];
      if (target) {
        e.preventDefault();
        tabManager.switchToTab(target.id);
      }
    }
    // 页面缩放：Ctrl + =/+ 放大，- 缩小，0 复位（对齐 Chrome，按站点记忆）
    if (e.ctrlKey && !e.altKey && !e.shiftKey) {
      const k = e.key;
      if (k === '=' || k === '+' || k === 'Add') {
        e.preventDefault();
        changeZoom('in');
      } else if (k === '-' || k === '_' || k === 'Subtract') {
        e.preventDefault();
        changeZoom('out');
      } else if (k === '0') {
        e.preventDefault();
        resetZoom();
      }
    }
  });

  async function changeZoom(delta) {
    const r = await window.electronAPI.invoke('set-zoom', { delta });
    if (r && r.success && typeof tabManager.showToast === 'function') {
      tabManager.showToast('缩放 ' + r.percent + '%');
    }
  }
  async function resetZoom() {
    const r = await window.electronAPI.invoke('set-zoom', { factor: 1 });
    if (r && r.success && typeof tabManager.showToast === 'function') {
      tabManager.showToast('缩放 100%');
    }
  }
})();

// ===== 快捷键速查浮层（F1 或 Ctrl+/）=====
(function setupShortcutsHelp() {
  const GROUPS = [
    { title: '标签页', items: [
      ['Ctrl + T', '新建标签页'],
      ['Ctrl + W', '关闭当前标签页'],
      ['Ctrl + Tab / Ctrl + Shift + Tab', '下一个 / 上一个标签页'],
      ['Ctrl + 1 ~ 8', '切换到第 N 个标签页'],
      ['Ctrl + 9', '切换到最后一个标签页'],
      ['Ctrl + Shift + T', '恢复最近关闭的标签页'],
      ['Ctrl + Shift + K', '复制当前标签页'],
      ['Ctrl + Shift + S', '立即休眠所有后台标签页（释放内存）'],
      ['中键点击标签', '关闭该标签页'],
    ]},
    { title: '导航', items: [
      ['Alt + ← / Alt + →', '后退 / 前进'],
      ['Ctrl + R / F5', '重新加载'],
      ['Ctrl + L / F6', '聚焦地址栏'],
      ['Ctrl + Enter', '裸域名自动补 .com'],
      ['Ctrl + U', '查看网页源代码'],
      ['Ctrl + H', '历史记录'],
      ['Ctrl + D', '添加书签'],
      ['Ctrl + Shift + B', '常驻书签栏开关'],
      ['Ctrl + = / -', '放大 / 缩小页面（按站点记忆）'],
      ['Ctrl + 0', '页面缩放复位 100%'],
    ]},
    { title: '阅读与查找', items: [
      ['Ctrl + F', '页内查找'],
      ['Ctrl + Shift + R', '阅读模式'],
      ['Ctrl + Shift + A', '标签页切换器'],
    ]},
    { title: '隐私与外观', items: [
      ['Ctrl + Shift + D', '暗色模式开关'],
      ['Ctrl + Shift + Delete', '清除浏览数据'],
      ['F1 / Ctrl + /', '本快捷键速查表'],
    ]},
  ];

  function kbd(text) {
    const el = document.createElement('kbd');
    el.textContent = text;
    el.style.cssText = 'display:inline-block;padding:2px 8px;border:1px solid #ccc;border-bottom-width:2px;border-radius:5px;background:#f7f7f7;font:12px/1.5 Consolas,monospace;color:#333;';
    return el;
  }

  function open() {
    if (document.getElementById('cosy-shortcuts-help')) return;
    const ov = document.createElement('div');
    ov.id = 'cosy-shortcuts-help';
    ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:10002;display:flex;align-items:flex-start;justify-content:center;padding:6vh 16px;';
    const panel = document.createElement('div');
    panel.style.cssText = 'background:#fff;border-radius:12px;width:640px;max-width:100%;max-height:84vh;overflow:auto;box-shadow:0 16px 48px rgba(0,0,0,.3);font:13px/1.6 system-ui,sans-serif;color:#222;';
    const h = document.createElement('h2');
    h.textContent = '键盘快捷键';
    h.style.cssText = 'margin:0;padding:18px 22px;font-size:17px;border-bottom:1px solid #eee;position:sticky;top:0;background:#fff;';
    panel.appendChild(h);
    const body = document.createElement('div');
    body.style.cssText = 'padding:12px 22px 22px;';
    GROUPS.forEach(g => {
      const gt = document.createElement('h3');
      gt.textContent = g.title;
      gt.style.cssText = 'margin:14px 0 6px;font-size:13px;color:#666;text-transform:uppercase;letter-spacing:.05em;';
      body.appendChild(gt);
      const table = document.createElement('div');
      g.items.forEach(([key, desc]) => {
        const row = document.createElement('div');
        row.style.cssText = 'display:flex;justify-content:space-between;gap:16px;padding:5px 0;border-bottom:1px solid #f5f5f5;';
        const d = document.createElement('span');
        d.textContent = desc;
        const k = document.createElement('span');
        k.appendChild(kbd(key));
        k.style.flexShrink = '0';
        row.appendChild(d);
        row.appendChild(k);
        table.appendChild(row);
      });
      body.appendChild(table);
    });
    panel.appendChild(body);
    ov.appendChild(panel);
    ov.addEventListener('click', (e) => { if (e.target === ov) ov.remove(); });
    document.addEventListener('keydown', function esc(ev) {
      if (ev.key === 'Escape') { ov.remove(); document.removeEventListener('keydown', esc); }
    });
    document.body.appendChild(ov);
  }

  document.addEventListener('keydown', (e) => {
    if (e.key === 'F1' || (e.ctrlKey && (e.key === '/' || e.key === '？'))) {
      e.preventDefault();
      const ov = document.getElementById('cosy-shortcuts-help');
      if (ov) ov.remove(); else open();
    }
  });
})();

// ===== 地址栏自动补全：书签 / 历史 / 已打开标签 =====
(function setupOmniboxAutocomplete() {
  const MAX_ITEMS = 8;
  let input = null;
  let panel = null;
  let items = [];
  let active = -1;

  function buildPanel() {
    panel = document.createElement('div');
    panel.id = 'cosy-omnibox-ac';
    panel.style.cssText = 'position:fixed;z-index:10003;background:var(--bg,#fff);color:var(--fg,#222);border:1px solid rgba(0,0,0,0.15);border-radius:8px;box-shadow:0 8px 28px rgba(0,0,0,.22);overflow:hidden;display:none;font:13px/1.4 system-ui,sans-serif;min-width:260px;';
    document.body.appendChild(panel);
  }

  function positionPanel() {
    const r = input.getBoundingClientRect();
    panel.style.left = r.left + 'px';
    panel.style.top = (r.bottom + 4) + 'px';
    panel.style.width = Math.max(260, r.width) + 'px';
  }

  function hide() {
    if (panel) panel.style.display = 'none';
    items = [];
    active = -1;
  }

  // 数据源合并去重：已打开标签页 > 书签 > 历史，按标签/标题/URL 子串匹配。
  function collect() {
    const seen = new Set();
    const out = [];
    const push = (url, title, kind) => {
      if (!url || seen.has(url)) return;
      seen.add(url);
      out.push({ url, title: title || url, kind });
    };
    const tabs = (typeof tabManager !== 'undefined' && tabManager.tabs) ? tabManager.tabs : [];
    tabs.forEach(t => { if (t.url && !t.url.startsWith('cosy://')) push(t.url, t.title, '标签'); });
    (tabManager.bookmarks || []).forEach(b => push(b.url, b.title, '书签'));
    (tabManager.history || []).forEach(h => push(h.url, h.title, '历史'));
    return out;
  }

  function score(text, q) {
    const i = text.toLowerCase().indexOf(q);
    if (i === -1) return -1;
    // 命中位置越靠前分越高
    return text.length - i;
  }

  function refresh() {
    const q = input.value.trim().toLowerCase();
    if (!q) { hide(); return; }
    const scored = [];
    for (const it of collect()) {
      const sUrl = score(it.url, q);
      const sTitle = score(it.title, q);
      const s = Math.max(sUrl, sTitle);
      if (s >= 0) scored.push({ ...it, _s: s });
    }
    items = scored.sort((a, b) => b._s - a._s).slice(0, MAX_ITEMS);
    active = items.length ? 0 : -1;
    render();
  }

  function render() {
    panel.innerHTML = '';
    if (items.length === 0) { hide(); return; }
    positionPanel();
    panel.style.display = 'block';
    items.forEach((it, idx) => {
      const row = document.createElement('div');
      row.style.cssText = 'display:flex;align-items:center;gap:10px;padding:7px 12px;cursor:pointer;';
      if (idx === active) row.style.background = 'rgba(0,120,212,0.12)';
      const tag = document.createElement('span');
      tag.textContent = it.kind;
      tag.style.cssText = 'flex-shrink:0;font-size:10px;opacity:0.6;border:1px solid rgba(0,0,0,.2);border-radius:4px;padding:0 5px;';
      const col = document.createElement('div');
      col.style.cssText = 'min-width:0;flex:1;';
      const t = document.createElement('div');
      t.textContent = it.title;
      t.style.cssText = 'overflow:hidden;text-overflow:ellipsis;white-space:nowrap;';
      const u = document.createElement('div');
      u.textContent = it.url;
      u.style.cssText = 'font-size:11px;opacity:0.6;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;';
      col.appendChild(t);
      col.appendChild(u);
      row.appendChild(tag);
      row.appendChild(col);
      row.addEventListener('mouseenter', () => { active = idx; highlight(); });
      row.addEventListener('mousedown', (e) => {
        // mousedown 先于 blur，避免面板被先隐藏
        e.preventDefault();
        choose(idx);
      });
      panel.appendChild(row);
    });
  }

  function highlight() {
    [...panel.children].forEach((r, i) => {
      r.style.background = i === active ? 'rgba(0,120,212,0.12)' : '';
    });
  }

  function choose(idx) {
    const it = items[idx];
    if (!it) return;
    input.value = it.url;
    hide();
    if (typeof tabManager !== 'undefined' && tabManager.navigateCurrentTab) {
      tabManager.navigateCurrentTab(it.url);
    }
  }

  function init() {
    input = document.getElementById('url-input');
    if (!input || input._acAttached) return;
    input._acAttached = true;
    buildPanel();
    input.addEventListener('input', refresh);
    input.addEventListener('focus', refresh);
    input.addEventListener('blur', () => setTimeout(hide, 120));
    input.addEventListener('keydown', (e) => {
      if (panel.style.display !== 'block') {
        if (e.key === 'ArrowDown') refresh();
        return;
      }
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (items.length) active = (active + 1) % items.length;
        highlight();
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (items.length) active = (active - 1 + items.length) % items.length;
        highlight();
      } else if (e.key === 'Enter' && active >= 0) {
        e.preventDefault();
        choose(active);
      } else if (e.key === 'Escape') {
        hide();
      }
    });
    window.addEventListener('resize', () => { if (panel.style.display === 'block') positionPanel(); });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();

// ===== 命令面板（Ctrl + Shift + P）：键盘即可触达常用命令 =====
(function setupCommandPalette() {
  const COMMANDS = [
    { label: '新建标签页', kw: 'new tab xinjian biaoqian', run: () => tabManager.createNewTab() },
    { label: '关闭当前标签页', kw: 'close tab guanbi', run: () => tabManager.closeTab(tabManager.currentTabId) },
    { label: '恢复刚关闭的标签页', kw: 'reopen huifu', run: () => reopenClosedTab() },
    { label: '重新加载当前页', kw: 'reload shuaxin chongxin jiazai', run: () => tabManager.reloadTab(tabManager.currentTabId) },
    { label: '回到主页', kw: 'home zhuye xinyebiao', run: () => tabManager.navigateCurrentTab('cosy://newtab') },
    { label: '聚焦地址栏', kw: 'address dizhilan focus jujiao', run: () => tabManager.focusAddressBar() },
    { label: '页内查找', kw: 'find chazhao zaiye nei', run: () => tabManager.toggleFindBar() },
    { label: '查看历史记录', kw: 'history lishi jilu', run: () => tabManager.showHistoryPanel() },
    { label: '打开下载列表', kw: 'download xiazai liebiao', run: () => tabManager.createNewTab('cosy://downloadlist') },
    { label: '打开设置', kw: 'settings shezhi', run: () => tabManager.createNewTab('cosy://setting') },
    { label: '清除浏览数据', kw: 'clear data qingchu shuju', run: () => tabManager.showClearDataDialog() },
    { label: '后退', kw: 'back houtui', run: () => tabManager.goBack() },
    { label: '前进', kw: 'forward qianjin', run: () => tabManager.goForward() },
    { label: '显示 / 隐藏书签栏', kw: 'bookmarks shuqianlan', run: () => tabManager.showBookmarksBar() },
    { label: '复制当前标签页', kw: 'duplicate fuzhi biaoqian', run: () => {
      const idx = tabManager.tabs.findIndex(t => t.id === tabManager.currentTabId);
      if (idx >= 0) window.electronAPI.invoke('duplicate-tab', idx);
    } },
    { label: '静音 / 取消静音当前标签页', kw: 'mute jingyin', run: () => {
      const cur = tabManager.tabs.find(t => t.id === tabManager.currentTabId);
      if (cur) window.electronAPI.invoke('set-tab-muted', { tabId: cur.id, muted: !cur.muted });
    } },
    { label: '放大页面', kw: 'zoom in fangda', run: () => window.electronAPI.invoke('set-zoom', { delta: 'in' }) },
    { label: '缩小页面', kw: 'zoom out suoxiao', run: () => window.electronAPI.invoke('set-zoom', { delta: 'out' }) },
    { label: '重置页面缩放', kw: 'zoom reset chongzhi suofang', run: () => window.electronAPI.invoke('set-zoom', { factor: 1 }) },
    { label: '打印当前页面', kw: 'print dayin', run: () => window.electronAPI.invoke('print-current-tab') },
    { label: '清除当前站点数据', kw: 'clear site data qingchu zhandian cookie', run: async () => {
      const cur = tabManager.tabs.find(t => t.id === tabManager.currentTabId);
      if (!cur || !/^https?:/.test(cur.url || '')) {
        tabManager.showToast('当前页面不是网站，无需清理站点数据');
        return;
      }
      let origin;
      try { origin = new URL(cur.url).origin; } catch { return; }
      const r = await window.electronAPI.invoke('clear-site-data', { origin });
      tabManager.showToast(r && r.success ? `已清除 ${origin} 的站点数据` : ('清除失败' + (r && r.error ? `：${r.error}` : '')));
      if (r && r.success) location.reload();
    } },
  ];

  let overlay, box, input, listEl, footer, matches, active;

  function build() {
    overlay = document.createElement('div');
    overlay.style.cssText = 'display:none;position:fixed;inset:0;z-index:10005;background:rgba(0,0,0,.35);';
    box = document.createElement('div');
    box.style.cssText = 'position:absolute;top:12vh;left:50%;transform:translateX(-50%);width:560px;max-width:92vw;background:var(--bg,#fff);color:var(--fg,#222);border:1px solid rgba(0,0,0,.15);border-radius:12px;box-shadow:0 18px 56px rgba(0,0,0,.32);overflow:hidden;font:13px/1.5 system-ui,sans-serif;';
    input = document.createElement('input');
    input.type = 'text';
    input.placeholder = '输入命令，如：设置、下载、历史…';
    input.style.cssText = 'display:block;width:100%;box-sizing:border-box;border:none;outline:none;padding:14px 16px;font-size:14px;background:transparent;color:inherit;';
    listEl = document.createElement('div');
    listEl.style.cssText = 'max-height:52vh;overflow:auto;border-top:1px solid rgba(0,0,0,.08);';
    footer = document.createElement('div');
    footer.textContent = '↑↓ 选择 · Enter 执行 · Esc 关闭';
    footer.style.cssText = 'padding:7px 16px;font-size:11px;opacity:.55;border-top:1px solid rgba(0,0,0,.08);';
    box.appendChild(input);
    box.appendChild(listEl);
    box.appendChild(footer);
    overlay.appendChild(box);
    overlay.addEventListener('mousedown', (e) => { if (e.target === overlay) hide(); });
    document.body.appendChild(overlay);
  }

  function score(cmd, q) {
    if (!q) return 0;
    const label = cmd.label.toLowerCase();
    const hay = (cmd.label + ' ' + cmd.kw).toLowerCase();
    const i = hay.indexOf(q);
    if (i < 0) return -1;
    return label.indexOf(q) >= 0 ? 2 : 1;
  }

  function refresh() {
    const q = input.value.trim().toLowerCase();
    matches = COMMANDS
      .map(c => ({ c, s: score(c, q) }))
      .filter(x => x.s >= 0)
      .sort((a, b) => b.s - a.s)
      .map(x => x.c);
    active = matches.length ? 0 : -1;
    render();
  }

  function render() {
    listEl.innerHTML = '';
    if (!matches.length) {
      const empty = document.createElement('div');
      empty.textContent = '没有匹配的命令';
      empty.style.cssText = 'padding:14px 16px;opacity:.55;';
      listEl.appendChild(empty);
      return;
    }
    matches.forEach((cmd, idx) => {
      const row = document.createElement('div');
      row.textContent = cmd.label;
      row.style.cssText = 'padding:9px 16px;cursor:pointer;';
      if (idx === active) row.style.background = 'rgba(0,120,212,.14)';
      row.addEventListener('mouseenter', () => { active = idx; paint(); });
      row.addEventListener('mousedown', (e) => { e.preventDefault(); pick(idx); });
      listEl.appendChild(row);
    });
  }

  function paint() {
    [...listEl.children].forEach((r, i) => {
      if (r.style) r.style.background = i === active ? 'rgba(0,120,212,.14)' : '';
    });
    const activeRow = listEl.children[active];
    if (activeRow && activeRow.scrollIntoView) activeRow.scrollIntoView({ block: 'nearest' });
  }

  function pick(idx) {
    const cmd = matches[idx];
    hide();
    if (cmd) {
      try { cmd.run(); } catch (e) { console.error('命令执行失败:', e); }
    }
  }

  function show() {
    if (!overlay) build();
    overlay.style.display = 'block';
    input.value = '';
    refresh();
    setTimeout(() => input.focus(), 0);
  }

  function hide() {
    if (overlay) overlay.style.display = 'none';
  }

  document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.shiftKey && (e.key === 'P' || e.key === 'p')) {
      e.preventDefault();
      if (overlay && overlay.style.display === 'block') hide();
      else show();
      return;
    }
    if (!overlay || overlay.style.display !== 'block') return;
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (matches.length) active = (active + 1) % matches.length;
      paint();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (matches.length) active = (active + matches.length - 1) % matches.length;
      paint();
    } else if (e.key === 'Enter') {
      e.preventDefault();
      pick(active);
    } else if (e.key === 'Escape') {
      e.preventDefault();
      hide();
    }
  });
})();

// ===== 底部下载栏（download shelf）=====
// Chrome/Edge 风格：下载开始时在窗口底部弹出紧凑卡片，显示文件名/进度/速度，
// 完成后可直接打开文件或所在目录，不必跳转完整下载页。数据全部来自主进程快照。
(function setupDownloadShelf() {
  const api = window.electronAPI;
  if (!api) return;

  let bar = null;
  let listEl = null;
  let state = new Map();

  function bytes(n) {
    n = Number(n) || 0;
    if (n < 1024) return n + ' B';
    const u = ['KB', 'MB', 'GB'];
    let v = n / 1024, i = 0;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return v.toFixed(v >= 100 ? 0 : 1) + ' ' + u[i];
  }

  function ensureBar() {
    if (bar) return;
    bar = document.createElement('div');
    bar.id = 'cosy-download-shelf';
    bar.style.cssText = [
      'position:fixed', 'left:8px', 'right:8px', 'bottom:8px', 'z-index:10000',
      'display:flex', 'flex-direction:column', 'gap:6px', 'pointer-events:none',
      'font:13px/1.4 system-ui,sans-serif',
    ].join(';');
    const head = document.createElement('div');
    head.style.cssText = 'pointer-events:auto;display:flex;align-items:center;justify-content:space-between;padding:4px 12px;background:rgba(255,255,255,.96);border:1px solid #ddd;border-radius:8px 8px 0 0;box-shadow:0 -2px 12px rgba(0,0,0,.08);';
    const title = document.createElement('span');
    title.textContent = '下载';
    title.style.cssText = 'font-weight:600;color:#333;';
    const actions = document.createElement('div');
    actions.style.cssText = 'display:flex;gap:10px;align-items:center;';
    const showAll = document.createElement('button');
    showAll.textContent = '全部显示';
    showAll.style.cssText = 'border:none;background:none;color:#1a73e8;cursor:pointer;font-size:12px;';
    showAll.addEventListener('click', () => api.send('shelf-show-all'));
    const closeAll = document.createElement('button');
    closeAll.textContent = '✕';
    closeAll.title = '关闭下载栏';
    closeAll.style.cssText = 'border:none;background:none;color:#666;cursor:pointer;font-size:13px;';
    closeAll.addEventListener('click', () => { bar.style.display = 'none'; });
    actions.appendChild(showAll);
    actions.appendChild(closeAll);
    head.appendChild(title);
    head.appendChild(actions);
    listEl = document.createElement('div');
    listEl.style.cssText = 'display:flex;flex-direction:column;gap:6px;';
    bar.appendChild(head);
    bar.appendChild(listEl);
    document.body.appendChild(bar);
  }

  function actionBtn(text, title, fn) {
    const b = document.createElement('button');
    b.textContent = text;
    b.title = title || text;
    b.style.cssText = 'border:none;background:none;color:#1a73e8;cursor:pointer;font-size:12px;padding:2px 4px;';
    b.addEventListener('click', fn);
    return b;
  }

  function paint(items) {
    if (!Array.isArray(items) || !items.length) return;
    ensureBar();
    bar.style.display = 'flex';
    listEl.innerHTML = '';
    items.forEach(d => {
      const row = document.createElement('div');
      row.style.cssText = 'pointer-events:auto;display:flex;align-items:center;gap:10px;padding:8px 12px;background:rgba(255,255,255,.97);border:1px solid #ddd;border-radius:8px;box-shadow:0 4px 14px rgba(0,0,0,.1);';

      const info = document.createElement('div');
      info.style.cssText = 'flex:1;min-width:0;';
      const name = document.createElement('div');
      name.textContent = d.filename || '下载';
      name.title = d.url || '';
      name.style.cssText = 'white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:#222;';
      const sub = document.createElement('div');
      sub.style.cssText = 'font-size:11px;color:#777;margin-top:2px;';
      info.appendChild(name);
      info.appendChild(sub);

      const ctl = document.createElement('div');
      ctl.style.cssText = 'display:flex;align-items:center;gap:4px;flex-shrink:0;';

      if (d.status === 'downloading' || d.status === 'pending') {
        const pct = d.totalBytes > 0 ? Math.min(100, Number(d.progress) || 0) : 0;
        sub.textContent = d.totalBytes > 0
          ? `${bytes(d.receivedBytes)} / ${bytes(d.totalBytes)} · ${pct.toFixed(0)}% · ${d.speed || ''}`
          : `${bytes(d.receivedBytes)} · ${d.speed || ''}`;
        ctl.appendChild(actionBtn('暂停', '暂停下载', () => api.send('pause-download', d.id)));
        ctl.appendChild(actionBtn('取消', '取消下载', () => api.send('cancel-download', d.id)));
      } else if (d.status === 'paused') {
        sub.textContent = `已暂停 · ${bytes(d.receivedBytes)}`;
        ctl.appendChild(actionBtn('继续', '继续下载', () => api.send('resume-download', d.id)));
        ctl.appendChild(actionBtn('取消', '取消下载', () => api.send('cancel-download', d.id)));
      } else if (d.status === 'complete') {
        sub.textContent = `已完成 · ${bytes(d.totalBytes || d.receivedBytes)}`;
        ctl.appendChild(actionBtn('打开', '打开文件', () => d.savePath && api.send('open-file', d.savePath)));
        ctl.appendChild(actionBtn('文件夹', '在文件夹中显示', () => d.savePath && api.send('open-folder', d.savePath)));
      } else {
        sub.textContent = '下载失败';
        sub.style.color = '#d93025';
        ctl.appendChild(actionBtn('重试', '重新下载', () => d.url && api.send('retry-download', { url: d.url })));
      }
      ctl.appendChild(actionBtn('✕', '移除此项', () => api.send('remove-download', d.id)));

      row.appendChild(info);
      row.appendChild(ctl);
      listEl.appendChild(row);
    });
  }

  api.on('download-shelf', (items) => {
    state = new Map((items || []).map(d => [d.id, d]));
    paint(items);
  });

  // Ctrl+J：现代浏览器的下载入口。shelf 可见时收起；不可见时重新拉取并展示，
  // 若当前没有任何下载项，则直接打开完整下载列表页。
  document.addEventListener('keydown', (e) => {
    if (!(e.ctrlKey && (e.key === 'j' || e.key === 'J'))) return;
    e.preventDefault();
    if (bar && bar.style.display === 'flex') {
      bar.style.display = 'none';
      return;
    }
    api.invoke('get-download-shelf').then(items => {
      if (Array.isArray(items) && items.length) paint(items);
      else api.send('shelf-show-all');
    }).catch(() => api.send('shelf-show-all'));
  });

  // 主界面加载后拉一次当前 shelf，覆盖“启动时已有下载”的场景。
  function init() {
    api.invoke('get-download-shelf').then(items => {
      if (Array.isArray(items) && items.length) paint(items);
    }).catch(() => {});
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => setTimeout(init, 300));
  } else {
    setTimeout(init, 300);
  }
})();

// ===== 网络状态提示横幅 =====
// 断网时在顶部给出一条不打断操作的提示条，恢复后自动消失。
// 优先用主进程权威状态（可感知虚拟网卡/代理变化），并用浏览器 online/offline 兜底。
(function setupNetworkBanner() {
  const api = window.electronAPI;
  if (!api) return;
  let banner = null;

  function show(text) {
    if (!banner) {
      banner = document.createElement('div');
      banner.style.cssText = [
        'position:fixed', 'top:8px', 'left:50%', 'transform:translateX(-50%)',
        'z-index:10002', 'padding:6px 16px', 'border-radius:16px',
        'background:rgba(217,48,37,.95)', 'color:#fff',
        'font:12px/1.4 system-ui,sans-serif', 'box-shadow:0 2px 10px rgba(0,0,0,.25)',
        'pointer-events:none', 'display:none',
      ].join(';');
      document.body.appendChild(banner);
    }
    banner.textContent = text;
    banner.style.display = 'block';
  }

  function hide() {
    if (banner) banner.style.display = 'none';
  }

  function apply(online) {
    if (online) hide();
    else show('网络已断开 · 你处于离线状态');
  }

  window.addEventListener('online', () => apply(true));
  window.addEventListener('offline', () => apply(false));
  if (typeof navigator !== undefined && navigator.onLine === false) apply(false);

  api.on('network-status-changed', (status) => {
    if (status && typeof status.online === 'boolean') apply(status.online);
  });
  api.invoke('get-network-status').then(s => {
    if (s && typeof s.online === 'boolean') apply(s.online);
  }).catch(() => {});
})();

// ===== 缩放级别浮层（OSD）：Ctrl+= / Ctrl+- / Ctrl+0 时短暂显示当前百分比 =====
(function setupZoomOsd() {
  const api = window.electronAPI;
  if (!api || !api.on) return;
  let osd = null;
  let hideTimer = null;

  function ensureOsd() {
    if (osd) return osd;
    osd = document.createElement('div');
    osd.setAttribute('aria-live', 'polite');
    osd.style.cssText = [
      'position:fixed', 'top:92px', 'right:24px', 'z-index:10003',
      'min-width:96px', 'padding:10px 18px', 'border-radius:10px',
      'background:rgba(32,33,36,.92)', 'color:#fff', 'text-align:center',
      'font:600 15px/1.3 system-ui,sans-serif', 'box-shadow:0 6px 20px rgba(0,0,0,.28)',
      'opacity:0', 'transform:translateY(-6px)',
      'transition:opacity .15s ease,transform .15s ease',
      'pointer-events:none', 'user-select:none',
    ].join(';');
    document.body.appendChild(osd);
    return osd;
  }

  function show(percent) {
    const el = ensureOsd();
    const pct = Number.isFinite(percent) ? Math.round(percent) : 100;
    el.textContent = pct === 100 ? '缩放 100%' : `缩放 ${pct}%`;
    el.style.opacity = '1';
    el.style.transform = 'translateY(0)';
    if (hideTimer) clearTimeout(hideTimer);
    hideTimer = setTimeout(() => {
      el.style.opacity = '0';
      el.style.transform = 'translateY(-6px)';
    }, 1100);
  }

  api.on('zoom-level-changed', (payload) => {
    if (!payload || typeof payload.percent !== 'number') return;
    show(payload.percent);
  });
})();

