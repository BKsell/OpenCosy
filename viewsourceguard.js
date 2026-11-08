'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'viewsource', prefix: 'VIEWSOURC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateViewsourceGuard: guard.evaluate,
  summarizeViewsourceGuard: guard.summarize,
  describeViewsourceGuard: guard.describe,
};
