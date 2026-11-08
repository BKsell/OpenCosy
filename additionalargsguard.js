'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'additionalargs', prefix: 'ADDITIONA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAdditionalargsGuard: guard.evaluate,
  summarizeAdditionalargsGuard: guard.summarize,
  describeAdditionalargsGuard: guard.describe,
};
