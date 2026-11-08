'use strict';

const { makeZhGuard } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'OCSPMUSTS', label: 'OCSP 必须钉住' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOcspmuststaple: guard.evaluate,
  summarizeOcspmuststaple: guard.summarize,
  describeOcspmuststaple: guard.describe,
};
