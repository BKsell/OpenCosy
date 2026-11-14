'use strict';

function loadLedgerOnce(d, loadedKey, ledgerName, storePathKey) {
  if (d[loadedKey]) return;
  d[loadedKey] = true;
  try {
    d[ledgerName].load(d.ledgerStore.readJSONStore(d[storePathKey], {}));
  } catch {}
}

module.exports = { loadLedgerOnce };
