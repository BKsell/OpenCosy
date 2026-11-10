'use strict';

const protocolIpc = require('./cosyipcprotocol');
const messagingIpc = require('./cosyipcmessaging');
const searchIpc = require('./cosyipcsearch');
const cosyipcextinstall = require('./cosyipcextinstall');
const cosycertipc = require('./cosycertipc');

function bindDeps(x) {
  protocolIpc.bindDeps(x);
  messagingIpc.bindDeps(x);
  searchIpc.bindDeps(x);
  cosyipcextinstall.bindDeps(x);
  cosycertipc.bindDeps(x);
}

function registerProtocolIpc() {
  protocolIpc.registerProtocolIpc();
}

function bootstrapRuntimeState() {
  protocolIpc.bootstrapRuntimeState();
}

function registerMessagingIpc() {
  messagingIpc.registerMessagingIpc();
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

module.exports = {
  bindDeps,
  registerProtocolIpc,
  bootstrapRuntimeState,
  registerMessagingIpc,
  registerFindIpc,
  registerTabOverviewIpc,
  registerExtensionIpc,
  registerCertificateIpc,
};
