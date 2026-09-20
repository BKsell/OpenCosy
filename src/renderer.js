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
  } catch (error) {
    console.error('解析设置失败:', error);
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
    this.initialize();
  }

  initialize() {
    this.setupEventListeners();
    this.setupIpcListeners();
    this.loadAndApplyThemeColor();
    this.loadBookmarks();
    this.loadHistory();
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
    } catch (error) {
      console.error('加载主题颜色失败:', error);
      this.applyThemeColor();
    }
  }

  async loadBookmarks() {
    try {
      const result = await window.electronAPI.invoke('get-bookmarks');
      if (result.success) {
        this.bookmarks = result.bookmarks;
      }
    } catch (error) {
      console.error('加载书签失败:', error);
    }
  }

  async loadHistory() {
    try {
      const result = await window.electronAPI.invoke('get-history');
      if (result.success) {
        this.history = result.history;
      }
    } catch (error) {
      console.error('加载历史记录失败:', error);
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
      toast.style.cssText = `
        position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%);
        background: var(--glass-bg-heavy, rgba(0,0,0,0.8)); color: var(--text, white);
        padding: 12px 24px; border-radius: 8px; z-index: 1000; opacity: 0;
        transition: opacity 0.3s ease; pointer-events: none;
        border: 1px solid var(--glass-border, rgba(255,255,255,0.1));
        backdrop-filter: blur(12px);
      `;
      document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.style.opacity = '1';
    setTimeout(() => { toast.style.opacity = '0'; }, 2000);
  }

  setupEventListeners() {
    document.getElementById('add-tab').addEventListener('click', () => this.createNewTab());
    document.getElementById('new-tab').addEventListener('click', () => this.createNewTab());
    document.getElementById('settings').addEventListener('click', () => this.createNewTab('cosy://setting'));
    document.getElementById('downloads').addEventListener('click', () => this.createNewTab('cosy://downloadlist'));
    document.getElementById('bookmarks').addEventListener('click', () => this.showBookmarksBar());
    document.getElementById('history').addEventListener('click', () => this.showHistoryPanel());
    document.getElementById('url-input').addEventListener('keypress', (e) => { if (e.key === 'Enter') this.navigateFromAddressBar(); });
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
    window.electronAPI.on('focus-address-bar', () => {
      const urlInput = document.getElementById('url-input');
      if (urlInput) {
        urlInput.focus();
        urlInput.select();
      }
    });
    window.electronAPI.on('show-history', () => this.showHistoryPanel());
  }

  toggleFullscreenUI(isFullscreen) {
    const elements = ['.titlebar', '.toolbar', '.tab-bar', '.status-bar'];
    elements.forEach(selector => {
      const el = document.querySelector(selector);
      if (el) el.style.display = isFullscreen ? 'none' : 'flex';
    });
  }

  showBookmarksBar() {
    let bar = document.getElementById('bookmarks-bar');
    if (bar) {
      bar.remove();
      return;
    }

    bar = document.createElement('div');
    bar.id = 'bookmarks-bar';
    bar.style.cssText = `
      position: fixed; top: 100px; left: 60px; right: 60px;
      background: var(--glass-bg-heavy, white);
      border: 1px solid var(--glass-border, #e0e0e0);
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      z-index: 100; max-height: 300px; overflow-y: auto;
      padding: 12px; backdrop-filter: blur(20px);
    `;

    if (this.bookmarks.length === 0) {
      bar.innerHTML = '<div style="text-align: center; color: var(--text-light, #999); padding: 20px;">暂无书签，按 Ctrl+D 添加书签</div>';
    } else {
      this.bookmarks.forEach(bookmark => {
        const item = document.createElement('div');
        item.style.cssText = 'padding: 8px; cursor: pointer; border-radius: 4px;';
        item.innerHTML = `<strong style="color: var(--text, #333);">${escapeHtml(bookmark.title)}</strong><br><small style="color: var(--text-light, #666);">${escapeHtml(bookmark.url)}</small>`;
        item.onmouseover = () => item.style.background = 'var(--glass-bg, rgba(0,0,0,0.05))';
        item.onmouseout = () => item.style.background = 'transparent';
        item.onclick = () => {
          this.createNewTab(bookmark.url);
          bar.remove();
        };
        bar.appendChild(item);
      });
    }

    document.body.appendChild(bar);
    setTimeout(() => {
      const closeHandler = (e) => {
        if (!bar.contains(e.target)) {
          bar.remove();
          document.removeEventListener('click', closeHandler);
        }
      };
      setTimeout(() => document.addEventListener('click', closeHandler), 100);
    });
  }

  showHistoryPanel() {
    let panel = document.getElementById('history-panel');
    if (panel) {
      panel.remove();
      return;
    }

    this.loadHistory();

    panel = document.createElement('div');
    panel.id = 'history-panel';
    panel.style.cssText = `
      position: fixed; top: 100px; right: 60px; width: 400px;
      background: var(--glass-bg-heavy, white);
      border: 1px solid var(--glass-border, #e0e0e0);
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      z-index: 100; max-height: 400px; overflow-y: auto;
      padding: 12px; backdrop-filter: blur(20px);
    `;

    const header = document.createElement('div');
    header.style.cssText = 'display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;';
    header.innerHTML = '<strong style="color: var(--text, #333);">历史记录</strong>';
    const clearBtn = document.createElement('button');
    clearBtn.textContent = '清除历史';
    clearBtn.style.cssText = 'padding: 4px 8px; border: 1px solid var(--border, #ddd); border-radius: 4px; cursor: pointer; background: var(--glass-bg, transparent); color: var(--text, #333);';
    clearBtn.onclick = async () => {
      await window.electronAPI.invoke('clear-history');
      this.history = [];
      panel.remove();
      this.showToast('历史记录已清除');
    };
    header.appendChild(clearBtn);
    panel.appendChild(header);

    if (this.history.length === 0) {
      panel.innerHTML += '<div style="text-align: center; color: var(--text-light, #999); padding: 20px;">暂无历史记录</div>';
    } else {
      this.history.forEach(item => {
        const entry = document.createElement('div');
        entry.style.cssText = 'padding: 8px; cursor: pointer; border-radius: 4px;';
        entry.innerHTML = `<strong style="color: var(--text, #333);">${escapeHtml(item.title)}</strong><br><small style="color: var(--text-light, #666);">${escapeHtml(item.url)}</small>`;
        entry.onmouseover = () => entry.style.background = 'var(--glass-bg, rgba(0,0,0,0.05))';
        entry.onmouseout = () => entry.style.background = 'transparent';
        entry.onclick = () => {
          this.createNewTab(item.url);
          panel.remove();
        };
        panel.appendChild(entry);
      });
    }

    document.body.appendChild(panel);
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
    } catch (error) {
      console.error('创建标签页失败:', error);
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

      if (tabData.favicon !== undefined) {
        this.updateFavicon(tabElement, tabData);
      }
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
    if (this.currentTabId) {
      if (!isSafeUrl(url)) url = 'cosy://newtab';
      const formattedUrl = this.formatUrl(url);
      const tabIndex = this.tabs.findIndex(t => t.id === this.currentTabId);
      if (tabIndex !== -1) {
        this.tabs[tabIndex].url = formattedUrl;
        this.updateAddressBar();
      }
      try {
        await window.electronAPI.invoke('navigate-tab', { tabId: this.currentTabId, url: formattedUrl });
      } catch (error) {
        console.error('导航失败:', error);
      }
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
    if (this.currentTabId) {
      const currentTab = this.tabs.find(tab => tab.id === this.currentTabId);
      if (currentTab) document.getElementById('url-input').value = currentTab.url;
    }
  }

  async goBack() {
    try {
      await window.electronAPI.invoke('navigate-back');
    } catch (error) {
      console.error('后退失败:', error);
    }
  }

  async goForward() {
    try {
      await window.electronAPI.invoke('navigate-forward');
    } catch (error) {
      console.error('前进失败:', error);
    }
  }

  async refresh() {
    if (this.currentTabId) {
      const currentTab = this.tabs.find(tab => tab.id === this.currentTabId);
      if (currentTab) await this.navigateCurrentTab(currentTab.url);
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
      this.updateTitlebarTitle();
    } else {
      tabBar.classList.add('collapsed');
      document.getElementById('collapse-tabbar').title = '展开标签页';
      window.electronAPI.send('toggle-tabbar-collapse', true);
      this.updateTitlebarTitle();
    }
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
