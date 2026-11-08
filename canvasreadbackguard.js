'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'canvasreadback', prefix: 'CANVASREA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateCanvasreadbackGuard: guard.evaluate,
  summarizeCanvasreadbackGuard: guard.summarize,
  describeCanvasreadbackGuard: guard.describe,
};
