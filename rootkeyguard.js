'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'rootkey', prefix: 'ROOTKEY' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRootkeyGuard: guard.evaluate,
  summarizeRootkeyGuard: guard.summarize,
  describeRootkeyGuard: guard.describe,
};
