'use strict';

function openSingletonTab(d, url) {
  const existing = d.tabs.findIndex(t => t && t.url === url);
  if (existing >= 0) {
    if (existing !== d.currentTabIndex) d.switchToTab(existing);
    return d.tabs[existing];
  }
  return d.createNewTab(url);
}

module.exports = { openSingletonTab };
