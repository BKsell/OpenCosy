'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'wsdl', prefix: 'WSDL' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateWsdlGuard: guard.evaluate,
  summarizeWsdlGuard: guard.summarize,
  describeWsdlGuard: guard.describe,
};
