'use strict';
let d = {};
function bindDeps(x) {
  d = x;
}
const cosyipcnetguardMod = require('./cosyipcnetguard_core');
const cosyipcdownloadshelfMod = require('./cosyipcdownloadshelf_core');
const cosyipctabsurfaceMod = require('./cosyipctabsurface_core');
const cosyipcsettingspanelMod = require('./cosyipcsettingspanel_core');
function registerNetworkGuards() {
  cosyipcnetguardMod.registerNetworkGuards(d);
}
function registerDownloadShelf() {
  cosyipcdownloadshelfMod.registerDownloadShelf(d);
}
function registerTabSurfaces() {
  cosyipctabsurfaceMod.registerTabSurfaces(d);
}
function registerSettingsPanels() {
  cosyipcsettingspanelMod.registerSettingsPanels(d);
}
module.exports = { bindDeps, registerNetworkGuards, registerDownloadShelf, registerTabSurfaces, registerSettingsPanels };
