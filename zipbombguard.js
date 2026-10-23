'use strict'

// zipbombguard.js —— 压缩包解压炸弹（ZIP/GBOMB）比率与层数守卫。
//
// 威胁模型：
//   浏览器会下载并（经系统/扩展）解压 zip、jar、docx 等。解压炸弹用极小压缩包展开成超大文件或
//   海量小文件，耗尽磁盘/内存；嵌套压缩包（zip 里放 zip）让"只看第一层"的检查失效。
//   本模块在解压"流式记账"阶段审计：
//     - 单文件压缩后→解压后膨胀比超过阈值；
//     - 累计解压字节超过总量上限；
//     - 文件条目数过多（小文件风暴）；
//     - 单个条目声明大小异常（声明极大但还没产出数据）；
//     - 嵌套层数过深。
//   纯数值记账，不做真实解压，不使用正则。

const ZB_REASON = Object.freeze({
  RATIO_HIGH: 'zip-entry-expansion-ratio-too-high',
  TOTAL_OVERFLOW: 'zip-total-uncompressed-size-over-limit',
  TOO_MANY_ENTRIES: 'zip-entry-count-over-limit',
  DECLARED_HUGE: 'zip-entry-declared-size-suspiciously-huge',
  NESTING_DEEP: 'zip-nested-archive-depth-over-limit',
  NEGATIVE_SIZE: 'zip-size-field-negative'
})

function defaultPolicy () {
  return {
    maxRatio: 200,
    maxTotalBytes: 2 * 1024 * 1024 * 1024,
    maxEntries: 100000,
    maxEntryDeclared: 1024 * 1024 * 1024,
    maxNestingDepth: 3
  }
}

class ZipBombGuard {
  constructor (policy) {
    this.policy = Object.assign({}, defaultPolicy(), policy || {})
    this.totalUncompressed = 0
    this.entries = 0
  }

  // 在开始解压一个条目前调用：declaredSize 为该条目声明的未压缩大小。
  auditEntry (compressedSize, declaredSize) {
    const findings = []
    const comp = Number(compressedSize)
    const declared = Number(declaredSize)
    if (declared < 0 || comp < 0) findings.push({ reason: ZB_REASON.NEGATIVE_SIZE })
    if (declared > this.policy.maxEntryDeclared) {
      findings.push({ reason: ZB_REASON.DECLARED_HUGE, detail: String(declared) })
    }
    // 压缩后极小却声明极大 → 高膨胀比（comp=0 时只要声明非零即可疑）
    if (declared > 0 && comp >= 0) {
      const ratio = comp === 0 ? Infinity : declared / comp
      if (ratio > this.policy.maxRatio) findings.push({ reason: ZB_REASON.RATIO_HIGH })
    }
    this.entries += 1
    if (this.entries > this.policy.maxEntries) findings.push({ reason: ZB_REASON.TOO_MANY_ENTRIES })
    return { safe: findings.length === 0, findings: findings }
  }

  // 在解压产出字节后累计调用。
  accountBytes (produced) {
    const findings = []
    const n = Number(produced)
    if (n < 0) return { safe: false, findings: [{ reason: ZB_REASON.NEGATIVE_SIZE }] }
    this.totalUncompressed += n
    if (this.totalUncompressed > this.policy.maxTotalBytes) {
      findings.push({ reason: ZB_REASON.TOTAL_OVERFLOW, detail: String(this.totalUncompressed) })
    }
    return { safe: findings.length === 0, findings: findings }
  }

  // 嵌套归档：进入一层压缩包调用。
  auditNesting (depth) {
    if (depth > this.policy.maxNestingDepth) {
      return { safe: false, findings: [{ reason: ZB_REASON.NESTING_DEEP, detail: String(depth) }] }
    }
    return { safe: true, findings: [] }
  }

  reset () {
    this.totalUncompressed = 0
    this.entries = 0
  }
}

module.exports = Object.freeze({
  ZB_REASON: ZB_REASON,
  defaultPolicy: defaultPolicy,
  ZipBombGuard: ZipBombGuard
})
