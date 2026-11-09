'use strict';
let d = {};
function bindDeps(x) {
  d = x;
  require('./cosyledgerpersist_part2').bindDeps(x);
}

function loadHttpsExceptions() {
  if (d.httpsExceptionsLoaded) return;
  d.httpsExceptionsLoaded = true;
  try {
    d.httpsExceptions.load(d.ledgerStore.readJSONStore(d.httpsExceptionStorePath, {}));
  } catch (e) { console.error('读取 HTTPS 例外失败:', e); }
}

module.exports = Object.assign({}, require('./cosyledgerpersist_part2'), {
  bindDeps,
  loadHttpsExceptions,
});
