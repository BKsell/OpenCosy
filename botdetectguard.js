'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'botdetect', prefix: 'BOTDETECT' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateBotdetectGuard: guard.evaluate,
  summarizeBotdetectGuard: guard.summarize,
  describeBotdetectGuard: guard.describe,
};
