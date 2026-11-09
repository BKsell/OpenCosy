'use strict';

const searchIpc = require('./cosyipcsearch');
const extensionIpc = require('./cosyipcextension');

function bindDeps(x) {
  searchIpc.bindDeps(x);
  extensionIpc.bindDeps(x);
}

function registerFindIpc() {
  searchIpc.registerFindIpc();
}

function registerTabOverviewIpc() {
  searchIpc.registerTabOverviewIpc();
}

function registerExtensionIpc() {
  extensionIpc.registerExtensionIpc();
}

function registerCertificateIpc() {
  extensionIpc.registerCertificateIpc();
}

module.exports = { bindDeps, registerFindIpc, registerTabOverviewIpc, registerExtensionIpc, registerCertificateIpc };
