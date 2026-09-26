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
    document.getElementById('url-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') this.navigateFromAddressBar(); });
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
        <span id="find-match-count" class="find-match-count"></span>
        <button id="find-prev" class="find-btn" title="上一个">▲</button>
        <button id="find-next" class="find-btn" title="下一个">▼</button>
        <button id="find-close" class="find-btn find-close" title="关闭 (Esc)">×</button>
      `;
      document.body.appendChild(findBar);

      const findInput = document.getElementById('find-input');
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
    this.findBarVisible = false;
    window.electronAPI.send('stop-find');
  }

  performFind(text, forward) {
    if (!text) return;
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

    tabElement.appendChild(this.createFaviconElement(tabData));

    const titleSpan = document.createElement('span');
    titleSpan.className = 'tab-title';
    titleSpan.textContent = tabData.title || '';

    const closeBtn = document.createElement('button');
    closeBtn.className = 'tab-close';
    closeBtn.textContent = '×';
    closeBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      this.closeTab(tabData.id);
    });

    tabElement.appendChild(titleSpan);
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
