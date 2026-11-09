'use strict';

let d = {};

function bindDeps(next) {
  d = next;
  require('./headerpipeline_part2').bindDeps(next);
}

module.exports = Object.assign({}, require('./headerpipeline_part2'), {
  bindDeps,
});
