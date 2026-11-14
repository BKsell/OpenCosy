'use strict';

const fsSync = require('fs');

function clearLedgerStore(load, list, storePath, persist) {
  load();
  list.length = 0;
  try {
    fsSync.unlinkSync(storePath);
  } catch {}
  persist();
  return true;
}

module.exports = { clearLedgerStore };
