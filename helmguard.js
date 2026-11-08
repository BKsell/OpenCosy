'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'helm', prefix: 'HELM' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateHelmGuard: guard.evaluate,
  summarizeHelmGuard: guard.summarize,
  describeHelmGuard: guard.describe,
};
