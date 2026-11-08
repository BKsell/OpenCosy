'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'regkeyhandler', prefix: 'REGKEYHAN' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateRegkeyhandlerGuard: guard.evaluate,
  summarizeRegkeyhandlerGuard: guard.summarize,
  describeRegkeyhandlerGuard: guard.describe,
};
