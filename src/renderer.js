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

window.electron = {
  minimize: () => window.electronAPI.minimize(),
  maximize: () => window.electronAPI.maximize(),
  close: () => window.electronAPI.close(),
};

class TabManager {
  constructor() {
    this.tabs = [];
    this.currentTabId = null;
    this.initialize();
  }

  initialize() {
    this.setupEventListeners();
    this.setupIpcListeners();
    this.loadAndApplyThemeColor();
  }

  loadAndApplyThemeColor() {
    try {
      const settings = JSON.parse(localStorage.getItem('cosySettings') || '{}');
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

  applyThemeColor(color = '#0078d4') {
    document.documentElement.style.setProperty('--theme-color', color);
  }

  setupEventListeners() {
    document.getElementById('add-tab').addEventListener('click', () => this.createNewTab());
    document.getElementById('new-tab').addEventListener('click', () => this.createNewTab());
    document.getElementById('settings').addEventListener('click', () => this.createNewTab('cosy://setting'));
    document.getElementById('downloads').addEventListener('click', () => this.createNewTab('cosy://downloadlist'));
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
  }

  toggleFullscreenUI(isFullscreen) {
    const elements = ['.titlebar', '.toolbar', '.tab-bar', '.status-bar'];
    elements.forEach(selector => {
      const el = document.querySelector(selector);
      if (el) el.style.display = isFullscreen ? 'none' : 'flex';
    });
  }

  async createNewTab(url) {
    const settings = JSON.parse(localStorage.getItem('cosySettings') || '{}');
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

  addTabToUI(tabData) {
    const tabsContainer = document.getElementById('tabs-container');
    const tabElement = document.createElement('div');
    tabElement.className = 'tab';
    tabElement.setAttribute('data-tab-id', tabData.id);

    let faviconHtml = '';
    if (tabData.favicon && isSafeUrl(tabData.favicon)) {
      faviconHtml = `<img src="${escapeHtml(tabData.favicon)}" class="tab-favicon" alt="" onerror="this.style.display='none'; this.parentNode.querySelector('.text-favicon').style.display='flex';">`;
    }

    let faviconText = 'N';
    if (tabData.title && tabData.title.trim()) faviconText = tabData.title.trim().charAt(0);
    faviconHtml += `<div class="text-favicon" style="display: ${tabData.favicon ? 'none' : 'flex'}">${escapeHtml(faviconText)}</div>`;

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

    tabElement.innerHTML = faviconHtml;
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
    const tabIndex = this.tabs.findIndex(tab => tab.id === tabId);
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

  updateTabUI(tabData) {
    const tabElement = document.querySelector(`[data-tab-id="${tabData.id}"]`);
    if (tabElement) {
      if (tabData.title) {
        const titleElement = tabElement.querySelector('.tab-title');
        if (titleElement) titleElement.textContent = tabData.title;
      }

      if (tabData.favicon && isSafeUrl(tabData.favicon)) {
        let faviconElement = tabElement.querySelector('.tab-favicon');
        let textFaviconElement = tabElement.querySelector('.text-favicon');

        if (!textFaviconElement) {
          textFaviconElement = document.createElement('div');
          textFaviconElement.className = 'text-favicon';
          textFaviconElement.style.display = 'none';
          let faviconText = 'N';
          if (tabData.title && tabData.title.trim()) faviconText = tabData.title.trim().charAt(0);
          textFaviconElement.textContent = faviconText;
          tabElement.insertBefore(textFaviconElement, tabElement.firstChild);
        }

        if (faviconElement) {
          if (faviconElement.tagName === 'IMG') {
            faviconElement.src = tabData.favicon;
            faviconElement.style.display = 'block';
            if (textFaviconElement) textFaviconElement.style.display = 'none';
          } else {
            const newFavicon = document.createElement('img');
            newFavicon.className = 'tab-favicon';
            newFavicon.src = tabData.favicon;
            newFavicon.alt = '';
            newFavicon.style.display = 'block';
            newFavicon.onerror = function() {
              this.style.display = 'none';
              if (textFaviconElement) textFaviconElement.style.display = 'flex';
            };
            faviconElement.replaceWith(newFavicon);
            if (textFaviconElement) textFaviconElement.style.display = 'none';
          }
        } else {
          const newFavicon = document.createElement('img');
          newFavicon.className = 'tab-favicon';
          newFavicon.src = tabData.favicon;
          newFavicon.alt = '';
          newFavicon.style.display = 'block';
          newFavicon.onerror = function() {
            this.style.display = 'none';
            if (textFaviconElement) textFaviconElement.style.display = 'flex';
          };
          tabElement.insertBefore(newFavicon, textFaviconElement);
          if (textFaviconElement) textFaviconElement.style.display = 'none';
        }
      }

      if (tabData.title) {
        const textFaviconElement = tabElement.querySelector('.text-favicon');
        if (textFaviconElement) {
          let faviconText = 'N';
          if (tabData.title && tabData.title.trim()) faviconText = tabData.title.trim().charAt(0);
          textFaviconElement.textContent = faviconText;
        }
      }
    }

    const tabIndex = this.tabs.findIndex(tab => tab.id === tabData.id);
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
    const tabIndex = this.tabs.findIndex(tab => tab.id === tabId);
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
      const tabIndex = this.tabs.findIndex(tab => tab.id === this.currentTabId);
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

    const settings = JSON.parse(localStorage.getItem('cosySettings') || '{}');
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

  async goBack() {}
  async goForward() {}

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
