'use strict';

const protocolIpc = require('./cosyipcprotocol');
const messagingIpc = require('./cosyipcmessaging');

function bindDeps(x) {
  protocolIpc.bindDeps(x);
  messagingIpc.bindDeps(x);
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

module.exports = { bindDeps, registerProtocolIpc, bootstrapRuntimeState, registerMessagingIpc };
