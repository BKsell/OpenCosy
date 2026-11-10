'use strict';

const searchIpc = require('./cosyipcsearch');
const cosyipcextinstall = require('./cosyipcextinstall');
const cosycertipc = require('./cosycertipc');

function bindDeps(x) {
  searchIpc.bindDeps(x);
  cosyipcextinstall.bindDeps(x);
  cosycertipc.bindDeps(x);
}

function registerFindIpc() {
  searchIpc.registerFindIpc();
}

function registerTabOverviewIpc() {
  searchIpc.registerTabOverviewIpc();
}

function registerExtensionIpc() {
  cosyipcextinstall.registerExtensionIpc();
}

function registerCertificateIpc() {
  cosycertipc.registerCertificateIpc();
}

module.exports = { bindDeps, registerFindIpc, registerTabOverviewIpc, registerExtensionIpc, registerCertificateIpc };
