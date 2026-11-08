'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'entityexpand', prefix: 'ENTITYEXP' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateEntityexpandGuard: guard.evaluate,
  summarizeEntityexpandGuard: guard.summarize,
  describeEntityexpandGuard: guard.describe,
};
