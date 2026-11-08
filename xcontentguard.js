'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'xcontent', prefix: 'XCONTENT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateXcontentGuard: guard.evaluate,
  summarizeXcontentGuard: guard.summarize,
  describeXcontentGuard: guard.describe,
};
