'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'downloaddest', prefix: 'DOWNLOADD' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateDownloaddestGuard: guard.evaluate,
  summarizeDownloaddestGuard: guard.summarize,
  describeDownloaddestGuard: guard.describe,
};
