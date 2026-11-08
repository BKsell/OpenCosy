'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'xts', prefix: 'XTS' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateXtsGuard: guard.evaluate,
  summarizeXtsGuard: guard.summarize,
  describeXtsGuard: guard.describe,
};
