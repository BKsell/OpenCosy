const { app, BrowserWindow, WebContentsView, ipcMain, session, protocol, Menu, MenuItem, dialog, shell } = require('electron');
const path = require('path');
const fs = require('fs').promises;
const fsSync = require('fs');
const os = require('os');

let mainWindow;
let tabs = [];
let currentTabIndex = 0;
let fileToOpen = null;

let downloads = [];
let currentDownloadInfo = null;
let isTabBarCollapsed = false;

class Tab {
  constructor(id, url = 'cosy://newtab') {
    this.id = id;
    this.url = url;
    this.title = '新标签页';
    this.favicon = null;
    this.view = null;
    this.isLoading = false;
    this.retry403 = false; // 用于标记是否已尝试重新加载403错误
  }
}

// 错误处理辅助函数
function getHttpStatusCode(errorCode) {
  const errorMap = {
    '-105': '404', // ERR_NAME_NOT_RESOLVED
    '-106': '400', // ERR_INTERNET_DISCONNECTED
    '-102': '404', // ERR_CONNECTION_REFUSED
    '-109': '404', // ERR_ADDRESS_UNREACHABLE
    '-118': '404', // ERR_CONNECTION_TIMED_OUT
    '-324': '500', // ERR_EMPTY_RESPONSE
    '-501': '501', // ERR_INSECURE_RESPONSE
    '-6': '404',   // ERR_FILE_NOT_FOUND
    '-3': '403'    // ERR_ACCESS_DENIED
  };
  return errorMap[errorCode.toString()] || '500';
}

function getErrorMessage(errorCode) {
  const messageMap = {
    '-105': '无法找到服务器',
    '-106': '网络连接已断开',
    '-102': '连接被拒绝',
    '-109': '地址无法访问',
    '-118': '连接超时',
    '-324': '服务器返回空响应',
    '-501': '不安全的响应',
    '-6': '文件未找到',
    '-3': '访问被拒绝'
  };
  return messageMap[errorCode.toString()] || '发生未知错误';
}

function getBrowserErrorText(errorCode) {
  const errorTextMap = {
    '-105': 'ERR_NAME_NOT_RESOLVED',
    '-106': 'ERR_INTERNET_DISCONNECTED',
    '-102': 'ERR_CONNECTION_REFUSED',
    '-109': 'ERR_ADDRESS_UNREACHABLE',
    '-118': 'ERR_CONNECTION_TIMED_OUT',
    '-324': 'ERR_EMPTY_RESPONSE',
    '-501': 'ERR_INSECURE_RESPONSE',
    '-6': 'ERR_FILE_NOT_FOUND',
    '-3': 'ERR_ACCESS_DENIED'
  };
  return errorTextMap[errorCode.toString()] || 'UNKNOWN_ERROR';
}

function createWindow() {
  // 如果窗口已存在，直接返回
  if (mainWindow && !mainWindow.isDestroyed()) {
    return;
  }

  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
      enableRemoteModule: false  // v2 安全加固: 禁用废弃remote模块，防止XSS访问主进程API
    },
    titleBarStyle: 'hidden',
    frame: false,
    show: false,
    icon: path.join(__dirname, 'ico.png')
  });

  // 读取设置以确定标签页布局
  const settingsPath = path.join(app.getPath('userData'), 'cosySettings.json');
  let tabLayout = 'horizontal';
  
  try {
    if (fsSync.existsSync(settingsPath)) {
      const settingsData = fsSync.readFileSync(settingsPath, 'utf-8');
      const settings = JSON.parse(settingsData);
      tabLayout = settings.tabLayout || 'horizontal';
    }
  } catch (error) {
    console.error('读取设置失败，使用默认水平布局:', error);
  }

  // 根据设置加载不同的HTML文件
  const htmlFile = tabLayout === 'vertical' ? 'src/index_vertical.html' : 'src/index.html';
  mainWindow.loadFile(htmlFile);

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    if (fileToOpen) {
      createNewTab(fileToOpen);
      fileToOpen = null;
    } else {
      // 读取用户的默认标签页设置
      const settingsPath = path.join(app.getPath('userData'), 'cosySettings.json');
      let defaultTabUrl = 'cosy://newtab'; // 默认值
      
      try {
        if (fsSync.existsSync(settingsPath)) {
          const settingsData = fsSync.readFileSync(settingsPath, 'utf-8');
          const settings = JSON.parse(settingsData);
          
          // 根据用户设置决定默认标签页
          if (settings.defaultTab) {
            if (settings.defaultTab === 'bing') {
              defaultTabUrl = 'https://www.bing.com';
            } else if (settings.defaultTab === 'custom' && settings.customUrl) {
              defaultTabUrl = settings.customUrl;
            }
          }
        }
      } catch (error) {
        console.error('读取设置失败，使用默认新标签页:', error);
      }
      
      createNewTab(defaultTabUrl);
    }
  });

  // 窗口大小改变时调整BrowserView尺寸
  mainWindow.on('resize', () => {
    updateBrowserViewBounds();
  });

  // 窗口移动时也调整BrowserView位置
  mainWindow.on('move', () => {
    updateBrowserViewBounds();
  });

  mainWindow.once('closed', () => {
    mainWindow = null;
  });
}

// 安全地获取URL协议
function getUrlProtocol(url) {
  try {
    return new URL(url).protocol;
  } catch {
    return null;
  }
}

function createNewTab(url = 'cosy://newtab') {
  const tabId = Date.now().toString();
  const tab = new Tab(tabId, url);
  
  // 为cosy协议的标签页设置默认图标，其他标签页使用loading.gif作为初始图标
  if (getUrlProtocol(url) === 'cosy:') {
    tab.favicon = 'file://' + path.join(__dirname, 'ico.png');
  } else {
    // 使用loading.gif作为初始加载图标
    tab.favicon = 'file://' + path.join(__dirname, 'src', 'loading.gif');
  }
  
  tabs.push(tab);
  currentTabIndex = tabs.length - 1;

  mainWindow.webContents.send('tab-created', {
    id: tab.id,
    url: tab.url,
    title: tab.title,
    favicon: tab.favicon
  });

  loadTabContent(tab);
  
  // 发送标签页切换事件，确保渲染进程更新选中状态和URL栏
  mainWindow.webContents.send('tab-switched', {
    id: tab.id,
    index: currentTabIndex
  });
  
  // 延迟更新浏览器视图位置，确保窗口尺寸已确定
  setTimeout(() => {
    updateBrowserViewBounds();
  }, 0);
  
  return tab;
}

function loadTabContent(tab) {
  if (!tab.view) {
    // 根据URL协议动态设置安全策略
    const isCosyProtocol = getUrlProtocol(tab.url) === 'cosy:';
    
    tab.view = new WebContentsView({
      webPreferences: {
        nodeIntegration: isCosyProtocol,        // cosy协议启用Node.js集成
        contextIsolation: !isCosyProtocol,      // 非cosy协议启用上下文隔离
        webSecurity: true,                      // 启用Web安全
        allowRunningInsecureContent: false,     // 禁止运行不安全内容
        sandbox: !isCosyProtocol,               // 非cosy协议启用沙箱模式
        enableRemoteModule: false,               // 禁用远程模块
        worldSafeExecuteJavaScript: true         // 启用安全JavaScript执行
      }
    });

    mainWindow.contentView.addChildView(tab.view);
    updateBrowserViewBounds();

    // 处理新窗口打开请求
    tab.view.webContents.setWindowOpenHandler(({ url, disposition }) => {
      // 如果是用户明确要求在新标签页中打开（如右键菜单）
      if (disposition === 'new-window' || disposition === 'foreground-tab') {
        // 创建新标签页并加载URL
        const newTab = createNewTab(url);
        switchToTab(tabs.indexOf(newTab));
      } else {
        // 其他情况在当前标签页中加载URL
        tab.url = url;
        tab.view.webContents.loadURL(url);
      }
      // 阻止默认的新窗口行为
      return { action: 'deny' };
    });

    // 处理导航事件，确保链接在当前标签页中打开
    tab.view.webContents.on('will-navigate', (event, navigationUrl) => {
      // 允许导航在当前标签页中进行
      tab.url = navigationUrl;
      mainWindow.webContents.send('tab-updated', {
        id: tab.id,
        url: navigationUrl
      });
    });

    // 处理重定向事件，确保重定向后URL栏正确更新
    tab.view.webContents.on('did-redirect-navigation', (event, url) => {
      // 更新标签页URL为重定向后的URL
      tab.url = url;
      mainWindow.webContents.send('tab-updated', {
        id: tab.id,
        url: url
      });
    });

    // 处理新窗口请求（如target="_blank"的链接）
    tab.view.webContents.on('new-window', (event, navigationUrl, frameName, disposition) => {
      event.preventDefault();
      
      // 根据打开方式决定如何处理
      if (disposition === 'new-window' || disposition === 'foreground-tab') {
        // 在新标签页中打开
        const newTab = createNewTab(navigationUrl);
        switchToTab(tabs.indexOf(newTab));
      } else {
        // 在当前标签页中打开
        tab.url = navigationUrl;
        tab.view.webContents.loadURL(navigationUrl);
      }
    });

    tab.view.webContents.on('page-title-updated', (event, title) => {
      tab.title = title;
      mainWindow.webContents.send('tab-updated', {
        id: tab.id,
        title: title
      });
    });

    tab.view.webContents.on('did-start-loading', () => {
      tab.isLoading = true;
      mainWindow.webContents.send('tab-loading', {
        id: tab.id,
        loading: true
      });
    });

    tab.view.webContents.on('did-stop-loading', () => {
      tab.isLoading = false;
      mainWindow.webContents.send('tab-loading', {
        id: tab.id,
        loading: false
      });
    });

    // 处理页面加载失败事件
    tab.view.webContents.on('did-fail-load', (event, errorCode, errorDescription, validatedURL, isMainFrame) => {
      if (isMainFrame) {
        const httpStatus = getHttpStatusCode(errorCode);
        
        // 检查是否是403错误且尚未重试过
        if (httpStatus === '403' && !tab.retry403) {
          // 标记已尝试重试
          tab.retry403 = true;
          
          // 透明地重新尝试加载一次
          console.log('检测到403错误，尝试重新加载:', validatedURL);
          tab.view.webContents.loadURL(validatedURL).catch(() => {
            // 如果重试仍然失败，显示错误页面
            showErrorPage(tab, errorCode, errorDescription, validatedURL);
          });
          return;
        }
        
        // 显示错误页面
        showErrorPage(tab, errorCode, errorDescription, validatedURL);
      }
    });
    
    // 显示错误页面的辅助函数
    function showErrorPage(tab, errorCode, errorDescription, validatedURL) {
      // 构建错误页面URL
      const errorParams = new URLSearchParams({
        code: getHttpStatusCode(errorCode),
        message: getErrorMessage(errorCode),
        reason: errorDescription,
        url: validatedURL,
        browserCode: errorCode,
        browserMessage: getBrowserErrorText(errorCode)
      });
      
      const errorUrl = `file://${__dirname}/src/error.html?${errorParams.toString()}`;
      tab.view.webContents.loadURL(errorUrl);
      
      // 更新标签页信息
      tab.url = validatedURL;
      tab.title = `错误 - ${getHttpStatusCode(errorCode)}`;
      
      mainWindow.webContents.send('tab-updated', {
        id: tab.id,
        url: validatedURL,
        title: tab.title
      });
    }

    tab.view.webContents.on('page-favicon-updated', (event, favicons) => {
      if (favicons.length > 0) {
        // 处理图标URL，确保格式正确
        let faviconUrl = favicons[0];
        
        // 如果是相对路径，转换为绝对路径
        if (faviconUrl.startsWith('/')) {
          const url = new URL(tab.url);
          faviconUrl = url.origin + faviconUrl;
        }
        
        // 如果是data URL或有效的URL，则使用
        if (faviconUrl.startsWith('data:') || faviconUrl.startsWith('http')) {
          tab.favicon = faviconUrl;
          mainWindow.webContents.send('tab-updated', {
            id: tab.id,
            favicon: tab.favicon
          });
        }
      }
    });

    // 处理右键菜单事件
    tab.view.webContents.on('context-menu', (event, params) => {
      const menu = new Menu();
      
      // 新标签页打开（如果点击的是链接）
      if (params.linkURL) {
        menu.append(new MenuItem({
          label: '在新标签页中打开',
          click: () => {
            createNewTab(params.linkURL);
          }
        }));
        menu.append(new MenuItem({ type: 'separator' }));
      }
      
      // 复制（如果有选中文本）
      if (params.selectionText) {
        menu.append(new MenuItem({
          label: '复制',
          role: 'copy'
        }));
      }
      
      // 剪切（如果有选中文本且在可编辑区域）
      if (params.selectionText && params.isEditable) {
        menu.append(new MenuItem({
          label: '剪切',
          role: 'cut'
        }));
      }
      
      // 粘贴（如果在可编辑区域）
      if (params.isEditable) {
        menu.append(new MenuItem({
          label: '粘贴',
          role: 'paste'
        }));
      }
      
      // 如果菜单有内容，添加分隔符
      if (menu.items.length > 0) {
        menu.append(new MenuItem({ type: 'separator' }));
      }
      
      // 总是显示开发者工具选项
      menu.append(new MenuItem({
        label: '开发者工具',
        click: () => {
          tab.view.webContents.toggleDevTools();
        }
      }));
      
      // 显示菜单
      menu.popup({
        window: mainWindow
      });
    });

    // 处理网页全屏事件
    tab.view.webContents.on('enter-html-full-screen', () => {
      // 保存当前WebContentsView的位置和大小
      const currentBounds = tab.view.bounds;
      tab.originalBounds = currentBounds;
      
      // 调整WebContentsView占据整个窗口
      const [width, height] = mainWindow.getSize();
      tab.view.setBounds({ 
        x: 0, 
        y: 0, 
        width: width, 
        height: height 
      });
      
      mainWindow.webContents.send('html-fullscreen-changed', { isFullscreen: true });
    });

    tab.view.webContents.on('leave-html-full-screen', () => {
      // 恢复WebContentsView的原始位置和大小
      if (tab.originalBounds) {
        tab.view.setBounds(tab.originalBounds);
        tab.originalBounds = null;
      }
      
      mainWindow.webContents.send('html-fullscreen-changed', { isFullscreen: false });
    });
  }

  // 总是根据当前URL加载内容
  const protocol = getUrlProtocol(tab.url);
  if (protocol === 'cosy:') {
    try {
      const urlObj = new URL(tab.url);
      const hostname = urlObj.hostname;
      
      const pageMap = {
        'setting': 'src/settings.html',
        'newtab': 'src/newtab.html',
        'extensions': 'src/extensions.html',
        'version': 'src/version.html',
        'download': 'src/download/index.html',
        'downloadlist': 'src/downloadlist.html'
      };
      
      const filePath = pageMap[hostname];
      if (filePath) {
        tab.view.webContents.loadFile(filePath);
      } else {
        // 未注册的cosy协议URL，跳转到错误页面
        const errorParams = new URLSearchParams({
          code: '404',
          message: '页面未找到',
          reason: '未注册的cosy协议地址',
          url: tab.url,
          browserCode: -3,
          browserMessage: 'ERR_UNKNOWN_COSY_URL'
        });
        const errorUrl = `file://${__dirname}/src/error.html?${errorParams.toString()}`;
        tab.view.webContents.loadURL(errorUrl);
        tab.title = '错误 - 404';
        tab.favicon = 'src/error.png';
        
        // 更新渲染进程中的标签页信息
        mainWindow.webContents.send('tab-updated', {
          id: tab.id,
          url: tab.url,
          title: tab.title
        });
      }
    } catch {
      // URL解析失败，跳转到错误页面
      const errorParams = new URLSearchParams({
        code: '400',
        message: '无效的URL',
        reason: '无法解析cosy协议地址',
        url: tab.url,
        browserCode: -3,
        browserMessage: 'ERR_UNKNOWN_COSY_URL'
      });
      const errorUrl = `file://${__dirname}/src/error.html?${errorParams.toString()}`;
      tab.view.webContents.loadURL(errorUrl);
      tab.title = '错误 - 400';
      tab.favicon = 'src/error.png';
      
      // 更新渲染进程中的标签页信息
      mainWindow.webContents.send('tab-updated', {
        id: tab.id,
        url: tab.url,
        title: tab.title
      });
    }
  } else {
    tab.view.webContents.loadURL(tab.url);
  }
}

function updateBrowserViewBounds() {
  if (tabs.length > 0 && currentTabIndex >= 0) {
    const tab = tabs[currentTabIndex];
    if (tab && tab.view) {
      const [width, height] = mainWindow.getSize();
      
      // 读取当前标签页布局设置
      const settingsPath = path.join(app.getPath('userData'), 'cosySettings.json');
      let tabLayout = 'horizontal';
      
      try {
        if (fsSync.existsSync(settingsPath)) {
          const settingsData = fsSync.readFileSync(settingsPath, 'utf-8');
          const settings = JSON.parse(settingsData);
          tabLayout = settings.tabLayout || 'horizontal';
        }
      } catch (error) {
        console.error('读取设置失败，使用默认水平布局:', error);
      }
      
      let browserViewX, browserViewY, browserViewWidth, browserViewHeight;
      
      if (tabLayout === 'vertical') {
        // 垂直标签页布局：左侧有标签页栏，没有水平标签栏
        const tabBarWidth = isTabBarCollapsed ? 50 : 200; // 折叠时宽度为50px，展开时为200px
        browserViewX = tabBarWidth; // 标签页栏宽度
        browserViewY = 75; // 32px标题栏 + 48px工具栏 - 5px调整 = 75px
        browserViewWidth = width - tabBarWidth; // 减去标签页栏宽度
        browserViewHeight = height - 75; // 延伸到窗口底部
      } else {
        // 水平标签页布局：顶部有水平标签栏
        browserViewX = 0;
        browserViewY = 116; // 32px标题栏 + 48px工具栏 + 36px标签栏 = 116px
        browserViewWidth = width;
        browserViewHeight = height - 116; // 延伸到窗口底部
      }
      
      tab.view.setBounds({ 
        x: browserViewX, 
        y: browserViewY, 
        width: browserViewWidth, 
        height: browserViewHeight 
      });
    }
  }
}

function switchToTab(tabIndex) {
  if (tabIndex >= 0 && tabIndex < tabs.length) {
    currentTabIndex = tabIndex;
    const tab = tabs[tabIndex];
    
    if (tab.view) {
      mainWindow.contentView.addChildView(tab.view);
      updateBrowserViewBounds();
    }
    
    mainWindow.webContents.send('tab-switched', {
      id: tab.id,
      index: tabIndex
    });
  }
}

function closeTab(tabIndex) {
  if (tabIndex >= 0 && tabIndex < tabs.length) {
    const tab = tabs[tabIndex];
    
    if (tab.view) {
      tab.view.webContents.destroy();
    }
    
    tabs.splice(tabIndex, 1);
    
    if (tabs.length === 0) {
      // 读取用户的默认标签页设置
      const settingsPath = path.join(app.getPath('userData'), 'cosySettings.json');
      let defaultTabUrl = 'cosy://newtab'; // 默认值
      
      try {
        if (fsSync.existsSync(settingsPath)) {
          const settingsData = fsSync.readFileSync(settingsPath, 'utf-8');
          const settings = JSON.parse(settingsData);
          
          // 根据用户设置决定默认标签页
          if (settings.defaultTab) {
            if (settings.defaultTab === 'bing') {
              defaultTabUrl = 'https://www.bing.com';
            } else if (settings.defaultTab === 'custom' && settings.customUrl) {
              defaultTabUrl = settings.customUrl;
            }
          }
        }
      } catch (error) {
        console.error('读取设置失败，使用默认新标签页:', error);
      }
      
      createNewTab(defaultTabUrl);
      currentTabIndex = 0;
    } else if (currentTabIndex >= tabs.length) {
      currentTabIndex = tabs.length - 1;
    }
    
    if (tabs.length > 0) {
      switchToTab(currentTabIndex);
    }
    
    mainWindow.webContents.send('tab-closed', tabIndex);
  }
}

// 下载管理器相关函数
function setupDownloadManager() {
  session.defaultSession.on('will-download', (event, item, webContents) => {
    const url = item.getURL();
    const filename = item.getFilename();
    const totalBytes = item.getTotalBytes();

    // 检查是否有预创建的 downloadInfo（来自"另存为"操作）
    let downloadInfo = downloads.find(d => d.url === url && d.item === null && d.isItemValid === false);
    let isNewDownload = false;

    if (downloadInfo) {
      // 更新已存在的 downloadInfo（来自"另存为"操作）
      downloadInfo.item = item;
      downloadInfo.filename = filename;
      downloadInfo.totalBytes = totalBytes;
      downloadInfo.isItemValid = true;
      downloadInfo.status = 'downloading';
    } else {
      // 阻止默认下载行为，让用户先选择保存方式
      event.preventDefault();

      // 创建新的 downloadInfo（不包含 item，因为下载被阻止了）
      downloadInfo = {
        id: Date.now().toString(),
        url: url,
        filename: filename,
        totalBytes: totalBytes,
        receivedBytes: 0,
        progress: 0,
        speed: '0 B/s',
        status: 'pending',
        startTime: Date.now(),
        savePath: null,
        item: null,
        lastUpdate: Date.now(),
        lastReceivedBytes: 0,
        isItemValid: false
      };

      downloads.push(downloadInfo);
      isNewDownload = true;
    }

    currentDownloadInfo = downloadInfo;

    // 如果是新的下载（不是"另存为"），打开下载页面让用户选择
    if (isNewDownload) {
      createNewTab('cosy://download');
      return;
    }

    // 设置保存路径（针对"另存为"的情况）
    if (downloadInfo.savePath) {
      item.setSavePath(downloadInfo.savePath);
    } else {
      const defaultSavePath = path.join(app.getPath('downloads'), filename);
      item.setSavePath(defaultSavePath);
      downloadInfo.savePath = defaultSavePath;
    }

    // 通知渲染进程下载已开始
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('download-status-changed', {
        id: downloadInfo.id,
        status: 'downloading'
      });
    }

    // 监听下载进度
    item.on('updated', (event, state) => {
      if (state === 'progressing') {
        const receivedBytes = item.getReceivedBytes();
        const totalBytes = item.getTotalBytes();
        const progress = totalBytes > 0 ? ((receivedBytes / totalBytes) * 100).toFixed(2) : 0;

        const now = Date.now();
        const timeDiff = (now - downloadInfo.lastUpdate) / 1000;

        if (timeDiff > 0) {
          const bytesDiff = receivedBytes - downloadInfo.lastReceivedBytes;
          const speed = bytesDiff / timeDiff;
          downloadInfo.speed = formatSpeed(speed);
        }

        downloadInfo.receivedBytes = receivedBytes;
        downloadInfo.progress = progress;
        downloadInfo.lastUpdate = now;
        downloadInfo.lastReceivedBytes = receivedBytes;
        downloadInfo.status = 'downloading';

        // 发送进度更新到渲染进程
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('download-progress', {
            id: downloadInfo.id,
            receivedBytes,
            totalBytes,
            progress,
            speed: downloadInfo.speed
          });
        }
      }
    });

    // 监听下载完成
    item.on('done', (event, state) => {
      downloadInfo.isItemValid = false;

      if (state === 'completed') {
        downloadInfo.status = 'complete';
        downloadInfo.savePath = item.getSavePath();

        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('download-complete', {
            id: downloadInfo.id,
            savePath: downloadInfo.savePath
          });
        }
      } else {
        downloadInfo.status = 'error';

        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('download-error', {
            id: downloadInfo.id
          });
        }
      }
    });

    // 如果是新的下载（不是"另存为"），打开下载页面
    if (isNewDownload) {
      createNewTab('cosy://download');
    }
  });
}

function formatSpeed(bytesPerSecond) {
  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
  let speed = bytesPerSecond;
  let unitIndex = 0;
  
  while (speed >= 1024 && unitIndex < units.length - 1) {
    speed /= 1024;
    unitIndex++;
  }
  
  return speed.toFixed(2) + ' ' + units[unitIndex];
}

function generateUserAgent() {
  const platform = os.platform();
  const arch = os.arch();
  const release = os.release();
  
  let osInfo;
  
  switch (platform) {
    case 'win32':
      if (release.startsWith('10.')) {
        osInfo = 'Windows NT 10.0';
      } else if (release.startsWith('6.3')) {
        osInfo = 'Windows NT 6.3';
      } else if (release.startsWith('6.2')) {
        osInfo = 'Windows NT 6.2';
      } else if (release.startsWith('6.1')) {
        osInfo = 'Windows NT 6.1';
      } else if (release.startsWith('6.0')) {
        osInfo = 'Windows NT 6.0';
      } else {
        osInfo = 'Windows NT 10.0';
      }
      osInfo += arch === 'x64' ? '; Win64; x64' : '; WOW64';
      break;
      
    case 'darwin':
      const macVersion = release.split('.').slice(0, 2).join('.');
      osInfo = `Macintosh; Intel Mac OS X ${macVersion.replace('.', '_')}`;
      break;
      
    case 'linux':
      if (arch === 'x64') {
        osInfo = 'X11; Linux x86_64';
      } else if (arch === 'arm64') {
        osInfo = 'X11; Linux aarch64';
      } else {
        osInfo = 'X11; Linux i686';
      }
      break;
      
    default:
      osInfo = 'X11; Unknown';
  }
  
return `Mozilla/5.0 (${osInfo}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.7559.60 OpenCosyBrowser/1.0.0`;
}

function setupProtocols() {
  // 协议注册将在app.whenReady()中调用
}

// 处理命令行参数
if (process.argv.length > 1) {
  const arg = process.argv[1];
  
  // 处理文件路径
  if (arg && (arg.endsWith('.html') || arg.endsWith('.htm'))) {
    fileToOpen = `file://${arg}`;
  }
  
  // 处理 http/https/cosy 协议 URL（Windows 协议启动时传递）
  if (arg && (arg.startsWith('http://') || arg.startsWith('https://') || arg.startsWith('cosy://'))) {
    fileToOpen = arg;
  }
}

// 处理文件打开事件
app.on('open-file', (event, filePath) => {
  event.preventDefault();
  
  if (filePath && (filePath.endsWith('.html') || filePath.endsWith('.htm'))) {
    const fileUrl = `file://${filePath}`;
    
    if (mainWindow && mainWindow.isReady()) {
      // 如果窗口已经打开，创建新标签页并选中
      const newTab = createNewTab(fileUrl);
      switchToTab(tabs.indexOf(newTab));
    } else {
      // 如果窗口未打开，设置fileToOpen变量
      fileToOpen = fileUrl;
    }
  }
});

app.whenReady().then(async () => {
  // 注册为默认协议处理器（支持 http, https 和 cosy）
  // v2 安全加固: 仅注册cosy自定义协议，移除http/https避免静默接管系统默认浏览器
  if (process.platform === 'win32') {
    app.setAsDefaultProtocolClient('cosy');
  }

  // 注册自定义协议
  protocol.registerFileProtocol('cosy', (request, callback) => {
    const url = request.url.replace('cosy://', '');
    let filePath;
    
    if (url === 'setting') {
      filePath = path.join(__dirname, 'src', 'settings.html');
    } else if (url === 'newtab') {
      filePath = path.join(__dirname, 'src', 'newtab.html');
    } else if (url === 'extensions') {
      filePath = path.join(__dirname, 'src', 'extensions.html');
    } else if (url === 'version') {
      filePath = path.join(__dirname, 'src', 'version.html');
    } else if (url === 'download') {
      filePath = path.join(__dirname, 'src', 'download', 'index.html');
    } else if (url === 'downloadlist') {
      filePath = path.join(__dirname, 'src', 'downloadlist.html');
    } else {
      filePath = path.join(__dirname, 'src', 'newtab.html');
    }
    
    callback({ path: filePath });
  });

  // v2 安全加固: file协议路径白名单，防止任意本地文件读取
  protocol.registerFileProtocol('file', (request, callback) => {
    try {
      const rawPath = decodeURIComponent(request.url.substr(7));
      const allowedDirs = [
        path.resolve(__dirname),
        path.resolve(app.getPath('downloads')),
        path.resolve(app.getPath('userData'))
      ];
      const resolvedPath = path.resolve(rawPath);
      const isAllowed = allowedDirs.some(dir =>
        resolvedPath.startsWith(dir + path.sep) || resolvedPath === dir
      );
      if (isAllowed) {
        callback({ path: resolvedPath });
      } else {
        console.log('file协议拒绝访问:', resolvedPath);
        callback({ error: -2 });
      }
    } catch (e) {
      console.log('file协议解析失败:', e.message);
      callback({ error: -2 });
    }
  });
  
  setupDownloadManager();
  
  // 动态生成用户代理
  const userAgent = generateUserAgent();
  session.defaultSession.setUserAgent(userAgent);
  
  createWindow();

  // 加载已启用的插件
  await loadEnabledExtensions();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

// 处理通过协议打开 URL 的事件（Windows）
app.on('open-url', (event, url) => {
  event.preventDefault();
  console.log('收到协议 URL:', url);
  
  // 确保窗口存在
  if (!mainWindow || mainWindow.isDestroyed()) {
    createWindow();
  }
  
  // 延迟处理，确保窗口已创建
  setTimeout(() => {
    if (url.startsWith('cosy://')) {
      createNewTab(url);
    } else if (url.startsWith('http://') || url.startsWith('https://')) {
      createNewTab(url);
    }
  }, 100);
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

ipcMain.on('window-control', (event, action) => {
  switch (action) {
    case 'minimize':
      mainWindow.minimize();
      break;
    case 'maximize':
      if (mainWindow.isMaximized()) {
        mainWindow.unmaximize();
      } else {
        mainWindow.maximize();
      }
      break;
    case 'close':
      mainWindow.close();
      break;
  }
});

// 监听标签页折叠/展开事件
ipcMain.on('toggle-tabbar-collapse', (event, collapsed) => {
  isTabBarCollapsed = collapsed;
  // 调整浏览器视图位置和大小
  updateBrowserViewBounds();
});

ipcMain.handle('navigate-tab', (event, { tabId, url }) => {
  const tab = tabs.find(t => t.id === tabId);
  if (tab) {
    tab.url = url;
    loadTabContent(tab);
    
    // 发送URL更新事件给渲染进程，更新地址栏显示
    mainWindow.webContents.send('tab-updated', {
      id: tab.id,
      url: url
    });
    
    return { success: true };
  }
  return { success: false };
});

ipcMain.handle('create-tab', (event, url) => {
  const tab = createNewTab(url);
  return { id: tab.id, index: tabs.length - 1 };
});

ipcMain.handle('close-tab', (event, tabIndex) => {
  closeTab(tabIndex);
  return { success: true };
});

ipcMain.handle('switch-tab', (event, tabIndex) => {
  switchToTab(tabIndex);
  return { success: true };
});

ipcMain.on('navigate-to-url', (event, url) => {
  if (url) {
    createNewTab(url);
  }
});

// 下载管理器IPC处理器
ipcMain.on('get-download-info', (event) => {
  if (currentDownloadInfo) {
    // 只发送可序列化的数据
    const info = {
      url: currentDownloadInfo.url,
      filename: currentDownloadInfo.filename,
      totalBytes: currentDownloadInfo.totalBytes || 0
    };
    event.reply('download-info', info);
  }
});

ipcMain.on('start-download', (event, data) => {
  if (currentDownloadInfo) {
    try {
      let savePath;
      if (data.savePath) {
        // v2 安全加固: 下载路径必须在下载目录内，防止任意文件写入
        const downloadsDir = path.resolve(app.getPath('downloads'));
        const resolvedSavePath = path.resolve(data.savePath);
        if (!resolvedSavePath.startsWith(downloadsDir + path.sep) && resolvedSavePath !== downloadsDir) {
          console.log('下载路径拒绝:', data.savePath);
          return;
        }
        savePath = resolvedSavePath;
      } else {
        const downloadPath = app.getPath('downloads');
        savePath = path.join(downloadPath, currentDownloadInfo.filename);
      }

      if (currentDownloadInfo.item && currentDownloadInfo.isItemValid) {
        // 如果已经有 DownloadItem（来自"另存为"），直接设置保存路径
        currentDownloadInfo.item.setSavePath(savePath);
        currentDownloadInfo.savePath = savePath;
        currentDownloadInfo.status = 'downloading';
      } else {
        // 如果没有 DownloadItem（新下载），设置保存路径并重新发起下载
        currentDownloadInfo.savePath = savePath;
        currentDownloadInfo.status = 'pending';
        currentDownloadInfo.item = null;
        currentDownloadInfo.isItemValid = false;
        
        // 重新发起下载
        session.defaultSession.downloadURL(currentDownloadInfo.url);
      }

      // 通知渲染进程下载已开始
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('download-started', { id: currentDownloadInfo.id });
      }
    } catch (error) {
      console.log('Start download error:', error.message);
      currentDownloadInfo.isItemValid = false;
      currentDownloadInfo.status = 'error';
    }
  }
});

ipcMain.on('show-save-dialog', (event, data) => {
  dialog.showSaveDialog(mainWindow, {
    defaultPath: path.join(app.getPath('downloads'), data.defaultName || 'download'),
    filters: [
      { name: 'All Files', extensions: ['*'] }
    ]
  }).then(result => {
    if (!result.canceled && result.filePath) {
      // 如果当前下载正在进行，先取消它
      if (currentDownloadInfo && currentDownloadInfo.item && currentDownloadInfo.isItemValid) {
        try {
          const state = currentDownloadInfo.item.getState();
          if (state === 'progressing' || state === 'interrupted') {
            currentDownloadInfo.item.cancel();
          }
          currentDownloadInfo.isItemValid = false;
          currentDownloadInfo.status = 'error';
        } catch (error) {
          console.log('Cancel download for save-as error:', error.message);
        }
      }

      // 更新当前 downloadInfo 的保存路径
      if (currentDownloadInfo) {
        currentDownloadInfo.savePath = result.filePath;
        currentDownloadInfo.status = 'pending';
        currentDownloadInfo.item = null;
        currentDownloadInfo.isItemValid = false;
      }

      // 重新发起下载到新路径
      if (data.url) {
        session.defaultSession.downloadURL(data.url);
      }
      
      // 通知渲染进程下载已开始（跳转到下载列表）
      event.reply('download-started', { id: currentDownloadInfo ? currentDownloadInfo.id : null });
    }
  });
});

ipcMain.on('get-downloads', (event) => {
  // 只发送可序列化的数据，排除item对象
  const serializableDownloads = downloads.map(d => ({
    id: d.id,
    url: d.url,
    filename: d.filename,
    totalBytes: d.totalBytes,
    receivedBytes: d.receivedBytes,
    progress: d.progress,
    speed: d.speed,
    status: d.status,
    startTime: d.startTime,
    savePath: d.savePath
  }));
  event.reply('downloads-list', serializableDownloads);
});

ipcMain.on('pause-download', (event, id) => {
  const download = downloads.find(d => d.id === id);
  if (download && download.item && download.isItemValid) {
    try {
      const state = download.item.getState();
      if (state === 'progressing') {
        download.item.pause();
        download.status = 'paused';
        
        // 通知渲染进程状态已更新
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('download-status-changed', {
            id: download.id,
            status: 'paused'
          });
        }
      }
    } catch (error) {
      console.log('Pause download error:', error.message);
      download.isItemValid = false;
      download.status = 'error';
      
      // 通知渲染进程状态已更新
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('download-status-changed', {
          id: download.id,
          status: 'error'
        });
      }
    }
  }
});

ipcMain.on('resume-download', (event, id) => {
  const download = downloads.find(d => d.id === id);
  if (download && download.item && download.isItemValid) {
    try {
      const state = download.item.getState();
      if (state === 'interrupted' || state === 'cancelled') {
        download.item.resume();
        download.status = 'downloading';
        
        // 通知渲染进程状态已更新
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('download-status-changed', {
            id: download.id,
            status: 'downloading'
          });
        }
      }
    } catch (error) {
      console.log('Resume download error:', error.message);
      download.isItemValid = false;
      download.status = 'error';
      
      // 通知渲染进程状态已更新
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('download-status-changed', {
          id: download.id,
          status: 'error'
        });
      }
    }
  }
});

ipcMain.on('cancel-download', (event, id) => {
  const download = downloads.find(d => d.id === id);
  if (download && download.item && download.isItemValid) {
    try {
      const state = download.item.getState();
      if (state === 'progressing' || state === 'interrupted') {
        download.item.cancel();
      }
      download.isItemValid = false;
      download.status = 'error';
      
      // 通知渲染进程状态已更新
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('download-status-changed', {
          id: download.id,
          status: 'error'
        });
      }
    } catch (error) {
      console.log('Cancel download error:', error.message);
      download.isItemValid = false;
      download.status = 'error';
      
      // 通知渲染进程状态已更新
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('download-status-changed', {
          id: download.id,
          status: 'error'
        });
      }
    }
  }
});

ipcMain.on('retry-download', (event, data) => {
  const { url, filename } = data;
  if (url) {
    session.defaultSession.downloadURL(url);
  }
});

ipcMain.on('remove-download', (event, id) => {
  const index = downloads.findIndex(d => d.id === id);
  if (index !== -1) {
    downloads.splice(index, 1);
    
    // 通知渲染进程下载列表已更新
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('download-removed', { id });
    }
  }
});

// v2 安全加固: open-file/open-folder 限制为下载目录内，防止打开任意可执行文件
function isPathInDownloads(filePath) {
  try {
    const downloadsDir = path.resolve(app.getPath('downloads'));
    const resolved = path.resolve(filePath);
    return resolved.startsWith(downloadsDir + path.sep) || resolved === downloadsDir;
  } catch {
    return false;
  }
}

ipcMain.on('open-file', (event, filePath) => {
  if (fsSync.existsSync(filePath) && isPathInDownloads(filePath)) {
    shell.openPath(filePath);
  } else {
    console.log('open-file拒绝:', filePath);
  }
});

ipcMain.on('open-folder', (event, filePath) => {
  if (fsSync.existsSync(filePath) && isPathInDownloads(filePath)) {
    shell.showItemInFolder(filePath);
  } else {
    console.log('open-folder拒绝:', filePath);
  }
});

ipcMain.on('clear-downloads', (event) => {
  // 彻底清空下载记录
  downloads = [];
  currentDownloadInfo = null;
  
  // 通知渲染进程下载列表已清空
  if (mainWindow && !mainWindow.isDestroyed()) {
    // 先发送清空事件，触发界面更新
    mainWindow.webContents.send('downloads-cleared');
    
    // 再发送成功反馈
    setTimeout(() => {
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('clear-downloads-success', '下载列表已成功清空');
      }
    }, 100);
  }
});

ipcMain.handle('get-current-tab', () => {
  if (tabs.length > 0 && currentTabIndex >= 0) {
    const tab = tabs[currentTabIndex];
    return {
      id: tab.id,
      url: tab.url,
      title: tab.title,
      favicon: tab.favicon,
      isLoading: tab.isLoading
    };
  }
  return null;
});

ipcMain.handle('get-all-tabs', () => {
  return tabs.map(tab => ({
    id: tab.id,
    url: tab.url,
    title: tab.title,
    favicon: tab.favicon,
    isLoading: tab.isLoading
  }));
});

// 关闭当前标签页
ipcMain.on('close-current-tab', (event) => {
  if (tabs.length > 0) {
    closeTab(currentTabIndex);
  }
});

// 创建新标签页
ipcMain.on('create-tab', (event, url) => {
  createNewTab(url);
});

// 显示更多选项菜单
ipcMain.on('show-more-options-menu', (event, position) => {
  const menu = new Menu();
  
  // 获取当前标签页的缩放级别
  let currentZoomLevel = 1.0;
  if (tabs.length > 0 && currentTabIndex >= 0) {
    const tab = tabs[currentTabIndex];
    if (tab.view && tab.view.webContents) {
      currentZoomLevel = tab.view.webContents.getZoomLevel();
    }
  }
  
  // 计算当前缩放百分比（正确的公式）
  const currentZoomPercent = Math.round((Math.pow(1.2, currentZoomLevel)) * 100);
  
  // 添加缩放菜单项（重置按钮在最上面）
  menu.append(new MenuItem({
    label: `重置缩放 (当前: ${currentZoomPercent}%)`,
    click: () => {
      if (tabs.length > 0 && currentTabIndex >= 0) {
        const tab = tabs[currentTabIndex];
        if (tab.view && tab.view.webContents) {
          tab.view.webContents.setZoomLevel(0);
        }
      }
    }
  }));
  
  menu.append(new MenuItem({
    label: '放大',
    click: () => {
      if (tabs.length > 0 && currentTabIndex >= 0) {
        const tab = tabs[currentTabIndex];
        if (tab.view && tab.view.webContents) {
          const currentLevel = tab.view.webContents.getZoomLevel();
          tab.view.webContents.setZoomLevel(currentLevel + 0.5);
        }
      }
    }
  }));
  
  menu.append(new MenuItem({
    label: '缩小',
    click: () => {
      if (tabs.length > 0 && currentTabIndex >= 0) {
        const tab = tabs[currentTabIndex];
        if (tab.view && tab.view.webContents) {
          const currentLevel = tab.view.webContents.getZoomLevel();
          tab.view.webContents.setZoomLevel(currentLevel - 0.5);
        }
      }
    }
  }));
  
  menu.append(new MenuItem({ type: 'separator' }));
  
  // 显示菜单在按钮点击位置附近
  menu.popup({
    window: mainWindow,
    x: position.x,
    y: position.y
  });
});

// 右键菜单处理
function createContextMenu(menuType, selectedText = '') {
  const menu = new Menu();
  
  if (menuType === 'selection') {
    // 选中文本时的右键菜单
    if (selectedText) {
      menu.append(new MenuItem({
        label: '复制',
        click: () => {
          if (mainWindow && mainWindow.webContents) {
            mainWindow.webContents.copy();
          }
        }
      }));
      
      menu.append(new MenuItem({ type: 'separator' }));
    }
    
    menu.append(new MenuItem({
      label: '主页',
      click: () => {
        if (tabs.length > 0 && currentTabIndex >= 0) {
          const tab = tabs[currentTabIndex];
          tab.url = 'cosy://newtab';
          loadTabContent(tab);
        }
      }
    }));
    
    menu.append(new MenuItem({
      label: '设置',
      click: () => {
        createNewTab('cosy://setting');
      }
    }));
    
    menu.append(new MenuItem({ type: 'separator' }));
    
    menu.append(new MenuItem({
      label: '开发者工具',
      click: () => {
        if (tabs.length > 0 && currentTabIndex >= 0) {
          const tab = tabs[currentTabIndex];
          if (tab.view && tab.view.webContents) {
            tab.view.webContents.toggleDevTools();
          }
        }
      }
    }));
  } else {
    // 空白位置的右键菜单
    menu.append(new MenuItem({
      label: '开发者工具',
      click: () => {
        if (tabs.length > 0 && currentTabIndex >= 0) {
          const tab = tabs[currentTabIndex];
          if (tab.view && tab.view.webContents) {
            tab.view.webContents.toggleDevTools();
          }
        }
      }
    }));
    
    menu.append(new MenuItem({
      label: '返回主页',
      click: () => {
        if (tabs.length > 0 && currentTabIndex >= 0) {
          const tab = tabs[currentTabIndex];
          tab.url = 'cosy://newtab';
          loadTabContent(tab);
        }
      }
    }));
    
    menu.append(new MenuItem({
      label: '设置',
      click: () => {
        createNewTab('cosy://setting');
      }
    }));
  }
  
  return menu;
}

// 插件管理相关函数
const userDataPath = path.join(os.homedir(), 'AppData', 'Roaming', 'OpenCosy', 'browser', 'userdata');
const extensionsPath = path.join(userDataPath, 'extensions');
const configPath = path.join(extensionsPath, 'config.json');

// 确保目录存在
async function ensureDirectories() {
  try {
    await fs.mkdir(userDataPath, { recursive: true });
    await fs.mkdir(extensionsPath, { recursive: true });
  } catch (error) {
    console.error('创建目录失败:', error);
  }
}

// 读取插件配置
async function readExtensionsConfig() {
  try {
    await ensureDirectories();
    if (fsSync.existsSync(configPath)) {
      const data = await fs.readFile(configPath, 'utf8');
      return JSON.parse(data);
    }
  } catch (error) {
    console.error('读取插件配置失败:', error);
  }
  return { extensions: [] };
}

// 保存插件配置
async function saveExtensionsConfig(config) {
  try {
    await ensureDirectories();
    await fs.writeFile(configPath, JSON.stringify(config, null, 2));
    return true;
  } catch (error) {
    console.error('保存插件配置失败:', error);
    return false;
  }
}

// 验证插件文件夹
async function validateExtensionFolder(folderPath) {
  try {
    const manifestPath = path.join(folderPath, 'manifest.json');
    if (!fsSync.existsSync(manifestPath)) {
      return { valid: false, error: '文件夹中未找到manifest.json文件' };
    }
    
    const manifestData = await fs.readFile(manifestPath, 'utf8');
    const manifest = JSON.parse(manifestData);
    
    // 基本验证
    if (!manifest.name) {
      return { valid: false, error: 'manifest.json中缺少name字段' };
    }
    if (!manifest.version) {
      return { valid: false, error: 'manifest.json中缺少version字段' };
    }
    if (!manifest.manifest_version) {
      return { valid: false, error: 'manifest.json中缺少manifest_version字段' };
    }
    
    return { valid: true, manifest };
  } catch (error) {
    return { valid: false, error: '读取manifest.json失败: ' + error.message };
  }
}

// 复制插件到扩展目录
async function copyExtensionToStorage(sourcePath, extensionId) {
  try {
    const targetPath = path.join(extensionsPath, extensionId);
    await fs.mkdir(targetPath, { recursive: true });
    
    // 简单的复制实现（实际应该递归复制所有文件）
    const files = await fs.readdir(sourcePath);
    for (const file of files) {
      const sourceFile = path.join(sourcePath, file);
      const targetFile = path.join(targetPath, file);
      
      const stat = await fs.stat(sourceFile);
      if (stat.isDirectory()) {
        await copyExtensionToStorage(sourceFile, path.join(extensionId, file));
      } else {
        await fs.copyFile(sourceFile, targetFile);
      }
    }
    
    return true;
  } catch (error) {
    console.error('复制插件失败:', error);
    return false;
  }
}

// 加载所有启用的插件
async function loadEnabledExtensions() {
  try {
    const config = await readExtensionsConfig();
    
    for (const ext of config.extensions) {
      if (ext.enabled) {
        await loadExtension(ext);
      }
    }
  } catch (error) {
    console.error('加载插件失败:', error);
  }
}

// 加载单个插件
async function loadExtension(extension) {
  try {
    const extensionPath = path.join(extensionsPath, extension.id);
    if (fsSync.existsSync(extensionPath)) {
      await session.defaultSession.loadExtension(extensionPath);
      console.log('插件加载成功:', extension.name);
    }
  } catch (error) {
    console.error('加载插件失败:', extension.name, error);
  }
}

// 卸载插件
async function unloadExtension(extensionId) {
  try {
    const extensions = session.defaultSession.getAllExtensions();
    for (const ext of extensions) {
      if (ext.id === extensionId) {
        await session.defaultSession.removeExtension(extensionId);
        break;
      }
    }
  } catch (error) {
    console.error('卸载插件失败:', extensionId, error);
  }
}

// IPC处理：添加插件
ipcMain.handle('add-extension', async (event, folderPath) => {
  try {
    // 验证插件文件夹
    const validation = await validateExtensionFolder(folderPath);
    if (!validation.valid) {
      return { success: false, error: validation.error };
    }
    
    const { manifest } = validation;
    const extensionId = `${manifest.name.replace(/[^a-zA-Z0-9]/g, '_')}_${manifest.version}`;
    
    // 读取现有配置
    const config = await readExtensionsConfig();
    
    // 检查是否已存在
    const existingExt = config.extensions.find(ext => ext.id === extensionId);
    if (existingExt) {
      return { success: false, error: '该插件已存在' };
    }
    
    // 复制插件文件
    const copySuccess = await copyExtensionToStorage(folderPath, extensionId);
    if (!copySuccess) {
      return { success: false, error: '复制插件文件失败' };
    }
    
    // 获取图标路径
    let iconPath = '';
    if (manifest.icons) {
      const iconSizes = Object.keys(manifest.icons).sort((a, b) => parseInt(b) - parseInt(a));
      if (iconSizes.length > 0) {
        iconPath = path.join(extensionsPath, extensionId, manifest.icons[iconSizes[0]]);
      }
    }
    
    // 添加到配置
    const newExtension = {
      id: extensionId,
      name: manifest.name,
      version: manifest.version,
      description: manifest.description || '',
      icon: iconPath,
      path: path.join(extensionsPath, extensionId),
      enabled: true,
      addedDate: new Date().toISOString()
    };
    
    config.extensions.push(newExtension);
    
    // 保存配置
    const saveSuccess = await saveExtensionsConfig(config);
    if (!saveSuccess) {
      return { success: false, error: '保存配置失败' };
    }
    
    return { success: true, extension: newExtension };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

// IPC处理：获取插件列表
ipcMain.handle('get-extensions', async () => {
  try {
    const config = await readExtensionsConfig();
    return { success: true, extensions: config.extensions };
  } catch (error) {
    return { success: false, error: error.message, extensions: [] };
  }
});

// IPC处理：切换插件状态
ipcMain.handle('toggle-extension', async (event, { id, enabled }) => {
  try {
    const config = await readExtensionsConfig();
    const extension = config.extensions.find(ext => ext.id === id);
    
    if (!extension) {
      return { success: false, error: '插件未找到' };
    }
    
    extension.enabled = enabled;
    
    const saveSuccess = await saveExtensionsConfig(config);
    if (!saveSuccess) {
      return { success: false, error: '保存配置失败' };
    }
    
    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

// IPC处理：移除插件
ipcMain.handle('remove-extension', async (event, id) => {
  try {
    const config = await readExtensionsConfig();
    const extensionIndex = config.extensions.findIndex(ext => ext.id === id);
    
    if (extensionIndex === -1) {
      return { success: false, error: '插件未找到' };
    }
    
    // 卸载插件
    await unloadExtension(id);
    
    // 删除插件文件
    const extensionPath = path.join(extensionsPath, id);
    if (fsSync.existsSync(extensionPath)) {
      await fs.rm(extensionPath, { recursive: true, force: true });
    }
    
    // 从配置中移除
    config.extensions.splice(extensionIndex, 1);
    
    const saveSuccess = await saveExtensionsConfig(config);
    if (!saveSuccess) {
      return { success: false, error: '保存配置失败' };
    }
    
    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
});

// IPC处理：浏览文件夹
ipcMain.handle('browse-folder', async () => {
  try {
    const result = await dialog.showOpenDialog(mainWindow, {
      title: '选择插件文件夹',
      properties: ['openDirectory']
    });
    
    if (!result.canceled && result.filePaths.length > 0) {
      return { success: true, path: result.filePaths[0] };
    } else {
      return { success: false, error: '用户取消选择' };
    }
  } catch (error) {
    return { success: false, error: error.message };
  }
});

// 处理右键菜单请求
ipcMain.on('show-context-menu', (event, menuType, selectedText) => {
  const menu = createContextMenu(menuType, selectedText);
  menu.popup();
});

// IPC处理：保存设置
ipcMain.on('save-settings', (event, settings) => {
  try {
    const settingsPath = path.join(app.getPath('userData'), 'cosySettings.json');
    fsSync.writeFileSync(settingsPath, JSON.stringify(settings, null, 2), 'utf-8');
    event.reply('settings-saved', { success: true });
  } catch (error) {
    console.error('保存设置失败:', error);
    event.reply('settings-saved', { success: false, error: error.message });
  }
});

// 主题颜色更新事件
ipcMain.on('update-theme-color', (event, color) => {
  // 通知主窗口更新主题颜色
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('update-theme-color', color);
  }
  
  // 通知所有标签页的浏览器视图更新主题颜色
  tabs.forEach(tab => {
    if (tab.view && tab.view.webContents) {
      tab.view.webContents.send('update-theme-color', color);
    }
  });
});

// 获取设置事件
ipcMain.on('get-settings', (event) => {
  try {
    const settingsPath = path.join(app.getPath('userData'), 'cosySettings.json');
    if (fsSync.existsSync(settingsPath)) {
      const settings = JSON.parse(fsSync.readFileSync(settingsPath, 'utf-8'));
      event.reply('settings-loaded', settings);
    } else {
      event.reply('settings-loaded', {});
    }
  } catch (error) {
    console.error('读取设置失败:', error);
    event.reply('settings-loaded', {});
  }
});

// 导出配置事件
ipcMain.on('export-config', async (event, content) => {
  try {
    const { dialog } = require('electron');
    
    // 打开保存对话框
    const result = await dialog.showSaveDialog(mainWindow, {
      title: '导出配置',
      defaultPath: 'cosy_config.inf',
      filters: [
        { name: '配置文件', extensions: ['inf'] },
        { name: '所有文件', extensions: ['*'] }
      ]
    });
    
    if (!result.canceled && result.filePath) {
      // 写入文件
      fsSync.writeFileSync(result.filePath, content, 'utf-8');
      event.reply('export-config-success', '配置文件导出成功！');
    } else {
      event.reply('export-config-canceled', '导出操作已取消');
    }
  } catch (error) {
    console.error('导出配置失败:', error);
    event.reply('export-config-error', '导出配置失败: ' + error.message);
  }
});
