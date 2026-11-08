'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'bluetoothpair', prefix: 'BLUETOOTH' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBluetoothpairGuard: guard.evaluate,
  summarizeBluetoothpairGuard: guard.summarize,
  describeBluetoothpairGuard: guard.describe,
};
