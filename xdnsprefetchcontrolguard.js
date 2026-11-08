'use strict';

const { makeDirectiveGuard } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'XDNSPREFE', label: 'X-DNS-Prefetch-Control' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateXdnsPrefetchcontrolGuard: guard.evaluate,
  describeXdnsPrefetchcontrolGuard: guard.describe,
};
