'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = __dirname;
const MODULES = ['cosyipcprotocol', 'cosyipcmessaging', 'cosyipcsearch', 'cosyipcextinstall', 'cosycertipc'];

function mainSource() {
  return fs.readFileSync(path.join(ROOT, 'main.js'), 'utf8');
}

function depsBlock(src) {
  const start = src.indexOf('cosyipcwireMod.bindDeps({');
  assert.notStrictEqual(start, -1, 'main.js 必须绑定 IPC 线束依赖');
  const end = src.indexOf('\n});\n', start);
  assert.notStrictEqual(end, -1, '绑定块必须有闭合');
  return src.slice(start, end);
}

test('IPC 线束依赖只绑定一次', () => {
  const src = mainSource();
  const hits = src.split('cosyipcwireMod.bindDeps(').length - 1;
  assert.strictEqual(hits, 1, '重复绑定会让后一次覆盖前一次的依赖');
});

test('单次绑定覆盖五个 IPC 子模块用到的全部依赖', () => {
  const block = depsBlock(mainSource());
  for (const name of MODULES) {
    const entry = path.join(ROOT, name + '.js');
    const core = path.join(ROOT, name + '_core.js');
    const text = fs.existsSync(core) && fs.statSync(core).size > fs.statSync(entry).size
      ? fs.readFileSync(core, 'utf8')
      : fs.readFileSync(entry, 'utf8');
    const used = new Set();
    const re = /\bd\.([A-Za-z0-9_]+)/g;
    let m;
    while ((m = re.exec(text)) !== null) used.add(m[1]);
    assert.ok(used.size > 0, name + ' 应通过 d 取依赖');
    for (const key of used) {
      const present = block.includes('get ' + key + '()') || block.includes('set ' + key + '(') || block.includes(key + ':');
      assert.ok(present, name + ' 依赖 ' + key + ' 未在绑定块中出现');
    }
  }
});
