'use strict';
const cosyledgerpersistMod = require('./cosyledgerpersist_core');
const cosyledgerledgerMod = require('./cosyledgerledger_core');
const cosyledgerbrandcertMod = require('./cosyledgerbrandcert_core');
const cosyledgersetupMod = require('./cosyledgersetup_core');
const LEDGER_PARTS = [cosyledgerpersistMod, cosyledgerledgerMod, cosyledgerbrandcertMod, cosyledgersetupMod];
function bindDeps(x) {
  for (const part of LEDGER_PARTS) part.bindDeps(x);
}
const ledgerApi = {};
for (const part of LEDGER_PARTS) {
  for (const name of Object.keys(part)) {
    if (name !== 'bindDeps') ledgerApi[name] = part[name];
  }
}
module.exports = Object.assign({ bindDeps }, ledgerApi);
