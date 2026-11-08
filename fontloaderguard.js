'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'fontloader', prefix: 'FONTLOADE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateFontloaderGuard: guard.evaluate,
  summarizeFontloaderGuard: guard.summarize,
  describeFontloaderGuard: guard.describe,
};
