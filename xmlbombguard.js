'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'xmlbomb', prefix: 'XMLBOMB' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateXmlbombGuard: guard.evaluate,
  summarizeXmlbombGuard: guard.summarize,
  describeXmlbombGuard: guard.describe,
};
