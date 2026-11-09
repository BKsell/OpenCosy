'use strict';

// urlclean.test.js —— 覆盖追踪参数清洗、主机特有参数、跳转包装解包与边界。

const test = require('node:test');
const assert = require('node:assert/strict');
const uc = require('./urlclean');
const { cleanUrl, unwrapRedirectTarget, cleanShareTarget, isWebUrl } = uc;

test('剥离 utm 与 fbclid 等营销参数，保留功能参数', () => {
  const r = cleanUrl('https://example.com/article?id=42&utm_source=x&fbclid=abc&page=2');
  assert.equal(r.changed, true);
  assert.equal(r.url, 'https://example.com/article?id=42&page=2');
  assert.deepEqual(r.removedKeys, ['utm_source', 'fbclid']);
});

test('无追踪参数时原样返回', () => {
  const url = 'https://example.com/p?a=1&b=2';
  const r = cleanUrl(url);
  assert.equal(r.changed, false);
  assert.equal(r.url, url);
});

test('保留 hash 与 path', () => {
  const r = cleanUrl('https://example.com/app#/route?utm_term=t');
  // utm 在 hash 内不属于 search，不应被误删（保持语义）。
  assert.equal(r.url, 'https://example.com/app#/route?utm_term=t');
});

test('非 http(s) 原样返回', () => {
  for (const s of ['mailto:a@b.com', 'javascript:alert(1)', 'file:///c:/x', 'cosy://newtab']) {
    assert.equal(cleanUrl(s).url, s);
    assert.equal(cleanUrl(s).changed, false);
  }
});

test('非法 URL 不抛错并原样返回', () => {
  assert.equal(cleanUrl('https://%%%bad').url, 'https://%%%bad');
});

test('主机特有参数只在对应域名删除', () => {
  const r1 = cleanUrl('https://www.google.com/search?q=hi&ved=xyz&ei=1');
  assert.equal(r1.url, 'https://www.google.com/search?q=hi');
  const r2 = cleanUrl('https://other.com/?ved=xyz');
  assert.equal(r2.changed, false);
});

test('youtube si 参数被清洗', () => {
  const r = cleanUrl('https://www.youtube.com/watch?v=abc&si=XYZ');
  assert.equal(r.url, 'https://www.youtube.com/watch?v=abc');
});

test('google 跳转包装解包', () => {
  const wrapped = 'https://www.google.com/url?q=https%3A%2F%2Ftarget.com%2Fx&sa=D&ust=1';
  const r = unwrapRedirectTarget(wrapped);
  assert.equal(r.unwrapped, true);
  assert.equal(r.url, 'https://target.com/x');
});

test('facebook l.php 解包', () => {
  const wrapped = 'https://l.facebook.com/l.php?u=https%3A%2F%2Fsite.org%2Fa&h=token';
  const r = unwrapRedirectTarget(wrapped);
  assert.equal(r.unwrapped, true);
  assert.equal(r.url, 'https://site.org/a');
});

test('路径不匹配的 google 链接不解包', () => {
  const wrapped = 'https://www.google.com/search?q=https%3A%2F%2Fx.com';
  const r = unwrapRedirectTarget(wrapped);
  assert.equal(r.unwrapped, false);
  assert.equal(r.url, wrapped);
});

test('解包目标非 http(s) 时不解包', () => {
  const wrapped = 'https://www.google.com/url?q=javascript%3Aalert(1)';
  const r = unwrapRedirectTarget(wrapped);
  assert.equal(r.unwrapped, false);
});

test('组合：解包并清洗', () => {
  const wrapped = 'https://www.google.com/url?q=https%3A%2F%2Ftarget.com%2Fp%3Fid%3D9%26utm_source%3Dg&sa=D';
  const r = cleanShareTarget(wrapped);
  assert.equal(r.unwrapped, true);
  assert.equal(r.url, 'https://target.com/p?id=9');
  assert.ok(r.removedKeys.includes('utm_source'));
});

test('isWebUrl 判定', () => {
  assert.equal(isWebUrl('http://a'), true);
  assert.equal(isWebUrl('https://a'), true);
  assert.equal(isWebUrl('ftp://a'), false);
});

test('删除全部参数后不应残留问号', () => {
  const r = cleanUrl('https://example.com/?utm_source=x');
  assert.equal(r.url, 'https://example.com/');
});

test('保留重复的功能参数', () => {
  const r = cleanUrl('https://example.com/?a=1&utm_source=x&a=2');
  assert.equal(r.url, 'https://example.com/?a=1&a=2');
});
