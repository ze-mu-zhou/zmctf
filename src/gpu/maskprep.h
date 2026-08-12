/**
 * maskprep.h:掩码 → GPU 两态拆分(主机端预计算,OpenCL/CUDA 两后端共用)。
 * 外部位:魔数除法展开(前 nOuter 位);内层位:尾部同居一个 u32 字的最多 4 位,
 * 字符集乘积 ≤ LOOP_CAP,预打包成位域表 innerTab(末位变化最快,与 maskCandidate 同构)。
 * 候选序号 = 外序号 × innerCount + 内层下标,总数语义与逐位展开完全一致。
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "divmagic.h"

#define MASK_LOOP_CAP 4096 // 内层位域表规模上限(16KB,constant 缓冲限内)

struct MaskGpuPrep {
  std::vector<uint8_t> csbuf;                 // 外部位字符集拼盘
  std::vector<uint32_t> csoff, cslen, csflg;  // 仅外部位
  std::vector<uint64_t> csmag;
  std::vector<uint32_t> innerTab;             // 内层位域(大端字节位已就位)
  uint32_t innerPos = 1;                      // 内层位数(≤4,同居末字)
  uint32_t innerCount = 1;                    // 内层表项数 = 内层各位字符集乘积
  uint32_t nOuter = 0;                        // 外部位数
  uint32_t nwords = 0;                        // 密钥总字数(ceil(npos/4))
  uint32_t lastWord = 0;                      // 内层位所在字下标
  uint64_t outerTotal = 0;                    // 外层组合数
};

inline MaskGpuPrep maskGpuPrep(const std::vector<std::string>& pos, uint64_t total) {
  MaskGpuPrep r;
  const uint32_t npos = (uint32_t)pos.size();
  // 内层位数:末字可用字节槽位内,自尾向前吃到乘积上限为止(至少 1 位)
  const uint32_t slots = ((npos - 1) % 4) + 1;
  uint32_t ic = 1;
  uint64_t prod = pos[npos - 1].size();
  while (ic < slots && ic < npos) {
    uint64_t nxt = prod * (uint64_t)pos[npos - 1 - ic].size();
    if (nxt > MASK_LOOP_CAP) break;
    prod = nxt;
    ic++;
  }
  r.innerPos = ic;
  r.innerCount = (uint32_t)prod; // 表项数 ≠ 位数:字面位(size 1)会使 prod < ic 位数
  r.nOuter = npos - ic;
  r.nwords = (npos + 3) / 4;
  r.lastWord = (npos - 1) / 4;
  r.outerTotal = total / prod;
  for (uint32_t k = 0; k < r.nOuter; k++) {
    r.csoff.push_back((uint32_t)r.csbuf.size());
    r.cslen.push_back((uint32_t)pos[k].size());
    DivMagic dm = divMagicFor((uint32_t)pos[k].size());
    r.csmag.push_back(dm.m);
    r.csflg.push_back(dm.flag);
    r.csbuf.insert(r.csbuf.end(), pos[k].begin(), pos[k].end());
  }
  // 内层位域表:末位最快;位 p 落在末字的字节 (p - 4*lastWord),大端高位在前
  r.innerTab.resize((size_t)prod);
  for (uint64_t i = 0; i < prod; i++) {
    uint64_t x = i;
    uint32_t word = 0;
    for (int j = (int)ic - 1; j >= 0; j--) {
      const std::string& cs = pos[npos - ic + j];
      uint32_t ch = (uint8_t)cs[x % cs.size()];
      x /= cs.size();
      uint32_t bytePos = (npos - ic + (uint32_t)j) - 4 * r.lastWord;
      word |= ch << (24 - 8 * bytePos);
    }
    r.innerTab[(size_t)i] = word;
  }
  return r;
}
