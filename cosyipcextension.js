'use strict';

let d = {};

function bindDeps(x) {
  d = x;
}

const cosyipcextinstall = require('./cosyipcextinstall');
const cosycertipc = require('./cosycertipc');

function bindDepsAll(x) {
  d = x;
  cosyipcextinstall.bindDeps(x);
  cosycertipc.bindDeps(x);
}

module.exports = Object.assign({}, cosyipcextinstall, cosycertipc, { bindDeps: bindDepsAll });
