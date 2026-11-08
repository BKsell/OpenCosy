'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'opcua', prefix: 'OPCUA' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateOpcuaGuard: guard.evaluate,
  summarizeOpcuaGuard: guard.summarize,
  describeOpcuaGuard: guard.describe,
};
