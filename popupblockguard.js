'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'popupblock', prefix: 'POPUPBLOC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePopupblockGuard: guard.evaluate,
  summarizePopupblockGuard: guard.summarize,
  describePopupblockGuard: guard.describe,
};
