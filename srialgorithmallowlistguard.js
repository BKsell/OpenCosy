'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'SRIALGORI', label: 'Subresource Integrity algorithm' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateSrialgorithmallowlistGuard: guard.evaluate,
  describeSrialgorithmallowlistGuard: guard.describe,
};
