'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'lastmod', prefix: 'LASTMOD' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateLastmodGuard: guard.evaluate,
  summarizeLastmodGuard: guard.summarize,
  describeLastmodGuard: guard.describe,
};
