'use strict'

// idnhomoglyphguard.js —— 国际化域名（IDN）同形字/混淆攻击守卫。
//
// 威胁模型：
//   钓鱼站用同形字符冒充品牌：用西里尔字母 а（U+0430）冒充拉丁 a，把 аpple.com 显示成 apple.com；
//   或混用多文字系统（Latin+Cyrillic+Greek）、使用极易混淆的数字（0/o、1/l/I）、全角字符等。
//   现代浏览器有同形字限制（一块文字系统策略），浏览器自身导航/书签匹配也应做检测：
//     - 单个标签内混用多个"文字系统块"即高度可疑；
//     - 含已知高危同形西里尔/希腊字符且其余为拉丁；
//     - 纯 Punycode（xn--）且其 unicode 形式含混合块。
//   纯字符码位判定，不使用正则。

const IDN_REASON = Object.freeze({
  MIXED_SCRIPTS: 'domain-label-mixes-multiple-unicode-scripts',
  CYRILLIC_LOOKALIKE: 'domain-contains-cyrillic-lookalike-of-latin',
  GREEK_LOOKALIKE: 'domain-contains-greek-lookalike-of-latin',
  NON_ASCII_IN_PUNY: 'punycode-label-decodes-to-non-ascii-needs-review',
  DIGIT_LETTER_AMBIG: 'domain-mixes-ambiguous-digits-and-letters'
})

// 与拉丁字母高度同形的西里尔小写码位（U+0430..）。
const CYRILLIC_LOOKALIKE = {
  0x0430: 'a', 0x0435: 'e', 0x043E: 'o', 0x0440: 'p', 0x0441: 'c',
  0x0443: 'y', 0x0445: 'x', 0x0455: 's', 0x0456: 'i',
  0x0458: 'j', 0x04BB: 'h', 0x04CF: 'l'
}
// 希腊同形：ο(U+03BF)、ε(U+03B5)、α(U+03B1)、ι(U+03B9)、υ(U+03C5)
const GREEK_LOOKALIKE = {
  0x03BF: 'o', 0x03B5: 'e', 0x03B1: 'a', 0x03B9: 'i', 0x03C5: 'u',
  0x03C1: 'p', 0x03BA: 'k', 0x03C4: 't'
}

function idnIsAscii (ch) {
  const c = ch.charCodeAt(0)
  return c < 0x80
}

function idnScriptOf (code) {
  if (code < 0x80) return 'latin'
  if (code >= 0x0400 && code <= 0x04FF) return 'cyrillic'
  if (code >= 0x0500 && code <= 0x052F) return 'cyrillic'
  if (code >= 0x0370 && code <= 0x03FF) return 'greek'
  if (code >= 0x4E00 && code <= 0x9FFF) return 'han'
  if (code >= 0x3040 && code <= 0x30FF) return 'kana'
  if (code >= 0xAC00 && code <= 0xD7AF) return 'hangul'
  if (code >= 0x0600 && code <= 0x06FF) return 'arabic'
  return 'other'
}

class IdnHomoglyphGuard {
  // domain：unicode 或含 xn-- 的主机名（小写无所谓，按码位判断）。
  evaluate (domain) {
    const d = String(domain || '')
    const findings = []
    const labels = d.split('.')
    for (const rawLabel of labels) {
      const label = rawLabel
      if (label.indexOf('xn--') === 0) {
        // 纯 punycode 标签无法在不解码时逐码位判定，标记需复核。
        findings.push({ reason: IDN_REASON.NON_ASCII_IN_PUNY, detail: label.slice(0, 12) })
        continue
      }
      const scripts = new Set()
      let hasLatinLetter = false
      for (let i = 0; i < label.length; i++) {
        const code = label.charCodeAt(i)
        if (idnIsAscii(label[i])) {
          const c2 = label[i]
          if ((c2 >= 'a' && c2 <= 'z') || (c2 >= 'A' && c2 <= 'Z')) hasLatinLetter = true
          scripts.add('latin')
        } else {
          const sc = idnScriptOf(code)
          scripts.add(sc)
          if (CYRILLIC_LOOKALIKE[code] !== undefined) findings.push({ reason: IDN_REASON.CYRILLIC_LOOKALIKE })
          if (GREEK_LOOKALIKE[code] !== undefined) findings.push({ reason: IDN_REASON.GREEK_LOOKALIKE })
        }
      }
      // 去掉 latin 后仍有 ≥1 个非拉丁文字块，且同时存在拉丁，视为混用。
      const nonLatin = Array.from(scripts).filter((s) => s !== 'latin')
      if (hasLatinLetter && nonLatin.length >= 1) findings.push({ reason: IDN_REASON.MIXED_SCRIPTS })
      if (nonLatin.length >= 2) findings.push({ reason: IDN_REASON.MIXED_SCRIPTS })
      this.checkAmbiguousDigits(label, findings)
    }
    return { safe: findings.length === 0, findings: findings }
  }

  // 0/o、1/l 连续混用在同标签（简单启发式）。
  checkAmbiguousDigits (label, findings) {
    let digit = false
    let confusableLetter = false
    for (let i = 0; i < label.length; i++) {
      const c = label[i]
      if (c === '0' || c === '1') digit = true
      if (c === 'o' || c === 'O' || c === 'l' || c === 'I' || c === 'i') confusableLetter = true
    }
    if (digit && confusableLetter) findings.push({ reason: IDN_REASON.DIGIT_LETTER_AMBIG })
  }
}

module.exports = Object.freeze({
  IDN_REASON: IDN_REASON,
  idnScriptOf: idnScriptOf,
  IdnHomoglyphGuard: IdnHomoglyphGuard
})
