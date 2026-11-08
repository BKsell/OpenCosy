'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'zoomfactor', prefix: 'ZOOMFACTO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateZoomfactorGuard: guard.evaluate,
  summarizeZoomfactorGuard: guard.summarize,
  describeZoomfactorGuard: guard.describe,
};
