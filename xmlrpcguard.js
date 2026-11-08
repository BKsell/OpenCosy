'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'xmlrpc', prefix: 'XMLRPC' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateXmlrpcGuard: guard.evaluate,
  summarizeXmlrpcGuard: guard.summarize,
  describeXmlrpcGuard: guard.describe,
};
