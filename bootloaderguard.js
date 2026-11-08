'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'bootloader', prefix: 'BOOTLOADE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBootloaderGuard: guard.evaluate,
  summarizeBootloaderGuard: guard.summarize,
  describeBootloaderGuard: guard.describe,
};
