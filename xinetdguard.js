'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'xinetd', prefix: 'XINETD' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateXinetdGuard: guard.evaluate,
  summarizeXinetdGuard: guard.summarize,
  describeXinetdGuard: guard.describe,
};
