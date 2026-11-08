'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'popupwindow', prefix: 'POPUPWIND' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluatePopupwindowGuard: guard.evaluate,
  summarizePopupwindowGuard: guard.summarize,
  describePopupwindowGuard: guard.describe,
};
