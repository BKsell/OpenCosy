const { ipcRenderer } = require('electron');

// Define window.electron before instantiating TabManager
window.electron = {
    minimize: () => {
        ipcRenderer.send('window-control', 'minimize');
    },
    maximize: () => {
        ipcRenderer.send('window-control', 'maximize');
    },
    close: () => {
        ipcRenderer.send('window-control', 'close');
    }
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
        this.setupKeyboardShortcuts();
        // 应用主题颜色
        this.loadAndApplyThemeColor();
        // 上报UI元素实际高度，主进程用于计算WebContentsView位置
        this.reportUiHeights();
        window.addEventListener('resize', () => this.reportUiHeights());
        // 主进程已经创建了第一个标签页，这里不需要再创建
    }

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            const ctrl = e.ctrlKey || e.metaKey;
            if (ctrl && e.key === 't') { e.preventDefault(); this.createNewTab(); }
            else if (ctrl && e.key === 'w') { e.preventDefault(); this.closeCurrentTab(); }
            else if (ctrl && e.key === 'r') { e.preventDefault(); this.refresh(); }
            else if (e.key === 'F5') { e.preventDefault(); this.refresh(); }
            else if (ctrl && e.key === 'l') { e.preventDefault(); this.focusAddressBar(); }
            else if (e.altKey && e.key === 'ArrowLeft') { e.preventDefault(); this.goBack(); }
            else if (e.altKey && e.key === 'ArrowRight') { e.preventDefault(); this.goForward(); }
            else if (ctrl && e.key === 'Tab') {
                e.preventDefault();
                const next = (this.tabs.findIndex(t => t.id === this.currentTabId) + 1) % this.tabs.length;
                this.switchToTab(this.tabs[next].id);
            }
            else if (ctrl && e.shiftKey && e.key === 'Tab') {
                e.preventDefault();
                const idx = this.tabs.findIndex(t => t.id === this.currentTabId);
                const prev = (idx - 1 + this.tabs.length) % this.tabs.length;
                this.switchToTab(this.tabs[prev].id);
            }
            else if (ctrl && e.key >= '1' && e.key <= '9') {
                e.preventDefault();
                const idx = parseInt(e.key) - 1;
                if (idx < this.tabs.length) this.switchToTab(this.tabs[idx].id);
            }
            else if (ctrl && e.key === 'p') { e.preventDefault(); ipcRenderer.send('print-page'); }
            else if (ctrl && e.key === 'f') { e.preventDefault(); ipcRenderer.send('find-in-page'); }
            else if (e.key === 'F11') { e.preventDefault(); ipcRenderer.send('toggle-fullscreen'); }
            else if (ctrl && e.key === '=') { e.preventDefault(); ipcRenderer.send('zoom-in'); }
            else if (ctrl && e.key === '-') { e.preventDefault(); ipcRenderer.send('zoom-out'); }
            else if (ctrl && e.key === '0') { e.preventDefault(); ipcRenderer.send('zoom-reset'); }
            else if (ctrl && e.key === 'j') { e.preventDefault(); this.createNewTab('cosy://downloadlist'); }
            else if (ctrl && e.key === ',') { e.preventDefault(); this.createNewTab('cosy://setting'); }
            else if (ctrl && e.shiftKey && e.key === 'T') { e.preventDefault(); ipcRenderer.send('restore-closed-tab'); }
            else if (e.key === 'F12') { e.preventDefault(); ipcRenderer.send('toggle-devtools'); }
            else if (ctrl && e.shiftKey && e.key === 'I') { e.preventDefault(); ipcRenderer.send('toggle-devtools'); }
            else if (ctrl && e.key === 'u') { e.preventDefault(); ipcRenderer.send('view-source'); }
            else if (ctrl && e.key === 's') { e.preventDefault(); ipcRenderer.send('save-page'); }
            else if (ctrl && e.shiftKey && e.key === 'C') {
                e.preventDefault();
                ipcRenderer.invoke('get-current-url').then(url => {
                    if (url) navigator.clipboard.writeText(url).catch(() => {});
                });
            }
            else if (ctrl && e.shiftKey && e.key === 'N') { e.preventDefault(); ipcRenderer.send('open-incognito'); }
        });
    }

    focusAddressBar() {
        const input = document.getElementById('url-input');
        if (input) { input.focus(); input.select(); }
    }

    closeCurrentTab() {
        if (this.currentTabId) this.closeTab(this.currentTabId);
    }
    
    loadAndApplyThemeColor() {
        try {
            const settings = JSON.parse(localStorage.getItem('cosySettings') || '{}');
            if (settings.themeColor) {
                this.applyThemeColor(settings.themeColor);
            } else {
                // 如果localStorage中没有主题颜色，尝试从文件系统中加载
                const { ipcRenderer } = require('electron');
                ipcRenderer.send('get-settings');
                // 默认应用蓝色
                this.applyThemeColor();
            }
        } catch (error) {
            console.error('加载主题颜色失败:', error);
            this.applyThemeColor();
        }
    }
    
    applyThemeColor(color = '#0078d4') {
        // 设置CSS变量
        document.documentElement.style.setProperty('--theme-color', color);
    }

    reportUiHeights() {
        const titlebar = document.querySelector('.titlebar');
        const toolbar = document.querySelector('.toolbar');
        const tabBar = document.querySelector('.tab-bar');
        const heights = {
            titlebar: titlebar ? titlebar.offsetHeight : 36,
            toolbar: toolbar ? toolbar.offsetHeight : 52,
            tabbar: tabBar ? tabBar.offsetHeight : 40
        };
        ipcRenderer.send('ui-heights', heights);
    }

    setupEventListeners() {
        document.getElementById('add-tab').addEventListener('click', () => {
            this.createNewTab();
        });

        document.getElementById('new-tab').addEventListener('click', () => {
            this.createNewTab();
        });

        document.getElementById('settings').addEventListener('click', () => {
            this.createNewTab('cosy://setting');
        });

        document.getElementById('downloads').addEventListener('click', () => {
            this.createNewTab('cosy://downloadlist');
        });

        document.getElementById('url-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.navigateFromAddressBar();
            }
        });

        document.getElementById('url-input').addEventListener('focus', (e) => {
            e.target.select();
        });

        // 中键关闭标签页
        const tabsContainer = document.getElementById('tabs-container');
        if (tabsContainer) {
            tabsContainer.addEventListener('mousedown', (e) => {
                if (e.button === 1) {
                    const tabEl = e.target.closest('.tab');
                    if (tabEl) {
                        e.preventDefault();
                        const tabId = tabEl.getAttribute('data-tab-id');
                        if (tabId) this.closeTab(tabId);
                    }
                }
            });
        }

        // 双击标签栏空白新建标签
        const tabBar = document.querySelector('.tab-bar');
        if (tabBar) {
            tabBar.addEventListener('dblclick', (e) => {
                if (!e.target.closest('.tab') && !e.target.closest('.new-tab-button')) {
                    this.createNewTab();
                }
            });
        }

        document.getElementById('go').addEventListener('click', () => {
            this.navigateFromAddressBar();
        });

        document.getElementById('back').addEventListener('click', () => {
            this.goBack();
        });

        document.getElementById('forward').addEventListener('click', () => {
            this.goForward();
        });

        document.getElementById('refresh').addEventListener('click', () => {
            this.refresh();
        });

        document.getElementById('home').addEventListener('click', () => {
            this.navigateCurrentTab('cosy://newtab');
        });

        document.getElementById('minimize').addEventListener('click', () => {
            window.electron.minimize();
        });

        document.getElementById('maximize').addEventListener('click', () => {
            window.electron.maximize();
        });

        document.getElementById('close').addEventListener('click', () => {
            window.electron.close();
        });

        // 折叠标签页按钮点击事件（仅在垂直模式下存在）
        const collapseTabbarBtn = document.getElementById('collapse-tabbar');
        if (collapseTabbarBtn) {
            collapseTabbarBtn.addEventListener('click', () => {
                this.toggleTabBarCollapse();
            });
        }

        // 更多选项按钮点击事件
        document.getElementById('more-options').addEventListener('click', (event) => {
            this.showMoreOptionsMenu(event);
        });

        // 添加右键菜单事件监听
        this.setupContextMenu();
        // 标签页右键菜单
        this.setupTabContextMenu();
    }

    setupTabContextMenu() {
        const tabsContainer = document.getElementById('tabs-container');
        if (!tabsContainer) return;
        tabsContainer.addEventListener('contextmenu', (e) => {
            const tabEl = e.target.closest('.tab');
            if (!tabEl) return;
            e.preventDefault();
            const tabId = tabEl.getAttribute('data-tab-id');
            const tabIndex = this.tabs.findIndex(t => t.id === tabId);
            if (tabIndex === -1) return;
            const menu = [
                { label: '重新加载', action: () => { ipcRenderer.send('reload-tab'); } },
                { label: '关闭标签页', action: () => this.closeTab(tabId) },
                { label: '关闭其他标签页', action: () => this.closeOtherTabs(tabIndex) },
                { label: '关闭右侧标签页', action: () => this.closeRightTabs(tabIndex) },
                { type: 'separator' },
                { label: '复制链接', action: () => {
                    const tab = this.tabs[tabIndex];
                    if (tab) navigator.clipboard.writeText(tab.url).catch(() => {});
                }}
            ];
            this.showCustomMenu(e.clientX, e.clientY, menu);
        });
    }

    showCustomMenu(x, y, items) {
        const old = document.getElementById('custom-context-menu');
        if (old) old.remove();
        const menu = document.createElement('div');
        menu.id = 'custom-context-menu';
        menu.style.cssText = `position:fixed;left:${x}px;top:${y}px;z-index:99999;background:#fff;border:1px solid #dfe4e1;border-radius:6px;box-shadow:0 4px 12px rgba(0,0,0,0.15);padding:4px 0;min-width:160px;font-size:13px;`;
        items.forEach(item => {
            if (item.type === 'separator') {
                const sep = document.createElement('div');
                sep.style.cssText = 'height:1px;background:#e0e0e0;margin:4px 0;';
                menu.appendChild(sep);
            } else {
                const mi = document.createElement('div');
                mi.textContent = item.label;
                mi.style.cssText = 'padding:6px 16px;cursor:pointer;';
                mi.addEventListener('mouseenter', () => { mi.style.background = '#f0f0f0'; });
                mi.addEventListener('mouseleave', () => { mi.style.background = 'transparent'; });
                mi.addEventListener('click', () => { item.action(); menu.remove(); });
                menu.appendChild(mi);
            }
        });
        document.body.appendChild(menu);
        const remove = () => { menu.remove(); document.removeEventListener('click', remove); };
        setTimeout(() => document.addEventListener('click', remove), 0);
    }

    closeOtherTabs(keepIndex) {
        const toClose = this.tabs.filter((_, i) => i !== keepIndex).map(t => t.id);
        toClose.forEach(id => this.closeTab(id));
    }

    closeRightTabs(fromIndex) {
        const toClose = this.tabs.slice(fromIndex + 1).map(t => t.id);
        toClose.forEach(id => this.closeTab(id));
    }

    setupIpcListeners() {
        ipcRenderer.on('tab-created', (event, tabData) => {
            this.addTabToUI(tabData);
        });

        ipcRenderer.on('tab-updated', (event, tabData) => {
            this.updateTabUI(tabData);
        });

        ipcRenderer.on('tab-loading', (event, tabData) => {
            this.setTabLoading(tabData.id, tabData.loading);
        });

        ipcRenderer.on('tab-switched', (event, tabData) => {
            this.switchToTabUI(tabData.id);
        });

        ipcRenderer.on('tab-closed', (event, tabIndex) => {
            this.removeTabFromUI(tabIndex);
        });

        ipcRenderer.on('html-fullscreen-changed', (event, data) => {
            this.toggleFullscreenUI(data.isFullscreen);
        });

        ipcRenderer.on('update-theme-color', (event, color) => {
            this.applyThemeColor(color);
        });

        ipcRenderer.on('settings-loaded', (event, settings) => {
            if (settings.themeColor) {
                this.applyThemeColor(settings.themeColor);
            }
        });
    }

    toggleFullscreenUI(isFullscreen) {
        const titlebar = document.querySelector('.titlebar');
        const toolbar = document.querySelector('.toolbar');
        const tabBar = document.querySelector('.tab-bar');
        const statusBar = document.querySelector('.status-bar');
        
        if (isFullscreen) {
            if (titlebar) titlebar.style.display = 'none';
            if (toolbar) toolbar.style.display = 'none';
            if (tabBar) tabBar.style.display = 'none';
            if (statusBar) statusBar.style.display = 'none';
        } else {
            if (titlebar) titlebar.style.display = 'flex';
            if (toolbar) toolbar.style.display = 'flex';
            if (tabBar) tabBar.style.display = 'flex';
            if (statusBar) statusBar.style.display = 'flex';
        }
    }

    async createNewTab(url) {
        // 读取用户的默认标签页设置
        const settings = JSON.parse(localStorage.getItem('cosySettings') || '{}');
        const defaultTab = settings.defaultTab || 'newtab';
        const customUrl = settings.customUrl || '';
        
        // 如果没有传入URL，则根据默认标签页设置生成URL
        if (!url) {
            switch (defaultTab) {
                case 'bing':
                    url = 'https://www.bing.com';
                    break;
                case 'custom':
                    url = customUrl || 'cosy://newtab'; // 如果自定义URL为空，则使用新标签页
                    break;
                case 'newtab':
                default:
                    url = 'cosy://newtab';
                    break;
            }
        }
        
        try {
            const result = await ipcRenderer.invoke('create-tab', url);
            return result;
        } catch (error) {
            console.error('创建标签页失败:', error);
        }
    }

    addTabToUI(tabData) {
        // v2 安全加固: 使用 DOM API 替代 innerHTML，防止网站标题/ID 注入 XSS
        const tabsContainer = document.getElementById('tabs-container');

        const tabElement = document.createElement('div');
        tabElement.className = 'tab';
        tabElement.setAttribute('data-tab-id', tabData.id);

        // 处理图标显示（仅允许 http/https/data 协议，防止 javascript: URL）
        if (tabData.favicon && this.isSafeFaviconUrl(tabData.favicon)) {
            const faviconImg = document.createElement('img');
            faviconImg.src = tabData.favicon;
            faviconImg.className = 'tab-favicon';
            faviconImg.alt = '';
            faviconImg.onerror = function () {
                this.style.display = 'none';
                const tf = this.parentNode.querySelector('.text-favicon');
                if (tf) tf.style.display = 'flex';
            };
            tabElement.appendChild(faviconImg);
        }

        // 文字图标作为备选（textContent 自动转义）
        let faviconText = 'N';
        if (tabData.title && tabData.title.trim()) {
            faviconText = tabData.title.trim().charAt(0);
        }
        const textFavicon = document.createElement('div');
        textFavicon.className = 'text-favicon';
        textFavicon.style.display = (tabData.favicon && this.isSafeFaviconUrl(tabData.favicon)) ? 'none' : 'flex';
        textFavicon.textContent = faviconText;
        tabElement.appendChild(textFavicon);

        // 标题使用 textContent 防止 XSS
        const titleSpan = document.createElement('span');
        titleSpan.className = 'tab-title';
        titleSpan.textContent = tabData.title || '';
        tabElement.appendChild(titleSpan);

        // 关闭按钮使用 addEventListener 替代内联 onclick，防止 ID 注入
        const closeBtn = document.createElement('button');
        closeBtn.className = 'tab-close';
        closeBtn.textContent = '×';
        closeBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            this.closeTab(tabData.id);
        });
        tabElement.appendChild(closeBtn);

        tabElement.addEventListener('click', (e) => {
            if (!e.target.classList.contains('tab-close')) {
                this.switchToTab(tabData.id);
            }
        });

        tabsContainer.appendChild(tabElement);
        this.tabs.push(tabData);

        if (this.tabs.length === 1) {
            this.switchToTab(tabData.id);
        }
    }

    // v2 安全加固: 校验 favicon URL 仅允许安全协议
    isSafeFaviconUrl(url) {
        if (!url || typeof url !== 'string') return false;
        try {
            const u = new URL(url);
            return ['http:', 'https:', 'data:'].includes(u.protocol);
        } catch {
            return false;
        }
    }

    async switchToTab(tabId) {
        const tabIndex = this.tabs.findIndex(tab => tab.id === tabId);
        if (tabIndex !== -1) {
            await ipcRenderer.invoke('switch-tab', tabIndex);
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
        document.querySelectorAll('.tab').forEach(tab => {
            tab.classList.remove('active');
        });
        
        const currentTab = document.querySelector(`[data-tab-id="${this.currentTabId}"]`);
        if (currentTab) {
            currentTab.classList.add('active');
        }
    }

    updateTabUI(tabData) {
        const tabElement = document.querySelector(`[data-tab-id="${tabData.id}"]`);
        if (tabElement) {
            if (tabData.title) {
                const titleElement = tabElement.querySelector('.tab-title');
                if (titleElement) {
                    titleElement.textContent = tabData.title;
                }
            }
            
            if (tabData.favicon) {
                let faviconElement = tabElement.querySelector('.tab-favicon');
                let textFaviconElement = tabElement.querySelector('.text-favicon');
                
                // 确保文字图标元素存在
                if (!textFaviconElement) {
                    textFaviconElement = document.createElement('div');
                    textFaviconElement.className = 'text-favicon';
                    textFaviconElement.style.display = 'none';
                    // 获取标题的第一个字符作为文字图标
                    let faviconText = 'N';
                    if (tabData.title && tabData.title.trim()) {
                        faviconText = tabData.title.trim().charAt(0);
                    }
                    textFaviconElement.textContent = faviconText;
                    tabElement.insertBefore(textFaviconElement, tabElement.firstChild);
                }
                
                // 如果是img元素，更新src；如果是div元素，替换为img元素
                if (faviconElement) {
                    if (faviconElement.tagName === 'IMG') {
                        faviconElement.src = tabData.favicon;
                        faviconElement.style.display = 'block';
                        if (textFaviconElement) {
                            textFaviconElement.style.display = 'none';
                        }
                    } else {
                        const newFavicon = document.createElement('img');
                        newFavicon.className = 'tab-favicon';
                        newFavicon.src = tabData.favicon;
                        newFavicon.alt = '';
                        newFavicon.style.display = 'block';
                        newFavicon.onerror = function() {
                            this.style.display = 'none';
                            if (textFaviconElement) {
                                textFaviconElement.style.display = 'flex';
                            }
                        };
                        faviconElement.replaceWith(newFavicon);
                        if (textFaviconElement) {
                            textFaviconElement.style.display = 'none';
                        }
                    }
                } else {
                    // 如果没有图标元素，创建一个
                    const newFavicon = document.createElement('img');
                    newFavicon.className = 'tab-favicon';
                    newFavicon.src = tabData.favicon;
                    newFavicon.alt = '';
                    newFavicon.style.display = 'block';
                    newFavicon.onerror = function() {
                        this.style.display = 'none';
                        if (textFaviconElement) {
                            textFaviconElement.style.display = 'flex';
                        }
                    };
                    tabElement.insertBefore(newFavicon, textFaviconElement);
                    if (textFaviconElement) {
                        textFaviconElement.style.display = 'none';
                    }
                }
            }
            
            // 如果更新了标题，同时更新文字图标
            if (tabData.title) {
                const textFaviconElement = tabElement.querySelector('.text-favicon');
                if (textFaviconElement) {
                    let faviconText = 'N';
                    if (tabData.title && tabData.title.trim()) {
                        faviconText = tabData.title.trim().charAt(0);
                    }
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
        if (tabElement) {
            if (loading) {
                tabElement.classList.add('loading');
            } else {
                tabElement.classList.remove('loading');
            }
        }
    }

    async closeTab(tabId) {
        const tabIndex = this.tabs.findIndex(tab => tab.id === tabId);
        if (tabIndex !== -1) {
            await ipcRenderer.invoke('close-tab', tabIndex);
        }
    }

    removeTabFromUI(tabIndex) {
        const tabElement = document.querySelectorAll('.tab')[tabIndex];
        if (tabElement) {
            tabElement.remove();
        }
        
        this.tabs.splice(tabIndex, 1);
        
        if (this.tabs.length > 0) {
            const newCurrentTab = this.tabs[Math.min(tabIndex, this.tabs.length - 1)];
            this.switchToTab(newCurrentTab.id);
        }
    }

    async navigateCurrentTab(url) {
        if (this.currentTabId) {
            const formattedUrl = this.formatUrl(url);
            
            // 立即更新当前标签页的URL和地址栏显示
            const tabIndex = this.tabs.findIndex(tab => tab.id === this.currentTabId);
            if (tabIndex !== -1) {
                this.tabs[tabIndex].url = formattedUrl;
                this.updateAddressBar();
            }
            
            try {
                await ipcRenderer.invoke('navigate-tab', {
                    tabId: this.currentTabId,
                    url: formattedUrl
                });
            } catch (error) {
                console.error('导航失败:', error);
            }
        }
    }

    navigateFromAddressBar() {
        const urlInput = document.getElementById('url-input');
        const url = urlInput.value.trim();
        
        if (url) {
            this.navigateCurrentTab(url);
        }
    }

    formatUrl(input) {
        // 使用URL对象来判断协议，而不是字符串匹配
        try {
            const urlObj = new URL(input);
            // 如果是有效的URL且协议是http, https, file, cosy之一，直接返回
            if (['http:', 'https:', 'file:', 'cosy:'].includes(urlObj.protocol)) {
                return input;
            }
        } catch {
            // 如果不是有效的URL，继续处理
        }
        
        if (input.includes('.') && !input.includes(' ')) {
            return 'https://' + input;
        }
        
        // 读取保存的搜索引擎设置
        const settings = JSON.parse(localStorage.getItem('cosySettings') || '{}');
        const searchEngine = settings.searchEngine || 'bing';
        
        // 根据设置选择搜索引擎
        let searchUrl;
        switch (searchEngine) {
            case 'google':
                searchUrl = 'https://www.google.com/search?q=';
                break;
            case 'baidu':
                searchUrl = 'https://www.baidu.com/s?wd=';
                break;
            case 'bing':
            default:
                searchUrl = 'https://www.bing.com/search?q=';
                break;
        }
        
        return searchUrl + encodeURIComponent(input);
    }

    async updateAddressBar() {
        if (this.currentTabId) {
            const currentTab = this.tabs.find(tab => tab.id === this.currentTabId);
            if (currentTab) {
                const urlInput = document.getElementById('url-input');
                urlInput.value = currentTab.url;
            }
        }
    }

    async goBack() {
        ipcRenderer.send('go-back');
    }

    async goForward() {
        ipcRenderer.send('go-forward');
    }

    async refresh() {
        ipcRenderer.send('reload-tab');
    }

    setupContextMenu() {
        // 监听右键菜单事件
        document.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            
            // 检查是否选中了文本
            const selection = window.getSelection();
            const selectedText = selection.toString().trim();
            
            let menuType = 'blank';
            if (selectedText) {
                menuType = 'selection';
            }
            
            // 发送右键菜单请求到主进程
            ipcRenderer.send('show-context-menu', menuType, selectedText);
        });
    }

    showMoreOptionsMenu(event) {
        // 发送更多选项菜单请求到主进程
        ipcRenderer.send('show-more-options-menu', {
            x: event.clientX,
            y: event.clientY
        });
    }

    toggleTabBarCollapse() {
        const tabBar = document.querySelector('.tab-bar-vertical');
        const isCollapsed = tabBar.classList.contains('collapsed');
        
        if (isCollapsed) {
            // 展开标签页
            tabBar.classList.remove('collapsed');
            document.getElementById('collapse-tabbar').title = '收缩标签页';
            // 通知主进程展开标签页
            ipcRenderer.send('toggle-tabbar-collapse', false);
            // 恢复默认标题
            this.updateTitlebarTitle();
        } else {
            // 折叠标签页
            tabBar.classList.add('collapsed');
            document.getElementById('collapse-tabbar').title = '展开标签页';
            // 通知主进程折叠标签页
            ipcRenderer.send('toggle-tabbar-collapse', true);
            // 更新为当前标签页标题
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
            if (currentTab && currentTab.title) {
                titlebarTitle.textContent = currentTab.title;
            } else {
                titlebarTitle.textContent = 'OpenCosy浏览器';
            }
        } else {
            // 恢复默认标题
            if (typeof COSY_CONSTANTS !== 'undefined' && COSY_CONSTANTS.APP_INFO) {
                titlebarTitle.textContent = COSY_CONSTANTS.APP_INFO.name;
            } else {
                titlebarTitle.textContent = 'OpenCosy浏览器';
            }
        }
    }
}

const tabManager = new TabManager();
