'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'ipfsgateway', prefix: 'IPFSGATEW' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateIpfsgatewayGuard: guard.evaluate,
  summarizeIpfsgatewayGuard: guard.summarize,
  describeIpfsgatewayGuard: guard.describe,
};
