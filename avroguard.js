'use strict';

const { makeGuard } = require('./guardkernel');

const guard = makeGuard({ base: 'avro', prefix: 'AVRO' });

module.exports = {
  LIMITS: guard.LIMITS,
  RULES: guard.RULES,
  evaluateAvroGuard: guard.evaluate,
  summarizeAvroGuard: guard.summarize,
  describeAvroGuard: guard.describe,
};
