'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'xmlparse', prefix: 'XMLPARSE' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateXmlparseGuard: guard.evaluate,
  summarizeXmlparseGuard: guard.summarize,
  describeXmlparseGuard: guard.describe,
};
