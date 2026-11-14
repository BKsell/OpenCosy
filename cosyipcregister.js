'use strict';
let d = {};
function bindDeps(x) {
  d = x;
}
const cosyipcnetguardMod = require('./cosyipcnetguard');
const cosyipcdownloadshelfMod = require('./cosyipcdownloadshelf');
const cosyipctabsurfaceMod = require('./cosyipctabsurface');
const cosyipcsettingspanelMod = require('./cosyipcsettingspanel');
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
