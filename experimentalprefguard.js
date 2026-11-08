'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'experimentalpref', prefix: 'EXPERIMEN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateExperimentalprefGuard: guard.evaluate,
  summarizeExperimentalprefGuard: guard.summarize,
  describeExperimentalprefGuard: guard.describe,
};
