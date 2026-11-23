/**
 * Client sidebar panel for `@tianacloud/dsh-remote`.
 *
 * Adapts automatically between:
 * - Local Host Mode (`!isRemote`): full management dashboard backed by local-only
 *   `/api/tiana-remote/admin/*` endpoints (unbound bind/create onboarding with live
 *   provision-status logs, status hero card + real ISO/IEC 18004 scannable QR code,
 *   masked E2EE key with reveal/copy/rotate, active sessions + Function token expiry
 *   & manual renew, rebind cloud app, P2P/STUN settings with draft protection).
 * - Remote Tunnel Mode (`isRemote`): restricted session status & device controls
 *   backed by `globalThis.__DSH_REMOTE_SHELL__` and redacted `/api/tiana-remote/public-status`
 *   (zero pairing keys, zero admin controls).
 */
(function registerDshRemoteClient() {
  // ---- Zero-dependency ISO/IEC 18004 QR Code Encoder (Byte Mode, EC Level M, Versions 1..10) ----
  const QR_GF_EXP = new Uint8Array(512);
  const QR_GF_LOG = new Uint8Array(256);
  (function initQrGalois() {
    let x = 1;
    for (let i = 0; i < 255; i += 1) {
      QR_GF_EXP[i] = x;
      QR_GF_LOG[x] = i;
      x <<= 1;
      if (x & 0x100) x ^= 0x11d;
    }
    for (let i = 255; i < 512; i += 1) {
      QR_GF_EXP[i] = QR_GF_EXP[i - 255];
    }
  })();

  function qrGfMul(a, b) {
    if (a === 0 || b === 0) return 0;
    return QR_GF_EXP[QR_GF_LOG[a] + QR_GF_LOG[b]];
  }

  function qrRsGeneratorPoly(degree) {
    let poly = [1];
    for (let i = 0; i < degree; i += 1) {
      const next = new Array(poly.length + 1).fill(0);
      const factor = QR_GF_EXP[i];
      for (let j = 0; j < poly.length; j += 1) {
        next[j] ^= poly[j];
        next[j + 1] ^= qrGfMul(poly[j], factor);
      }
      poly = next;
    }
    return poly;
  }

  function qrRsComputeEc(data, ecCount) {
    const gen = qrRsGeneratorPoly(ecCount);
    const rem = new Uint8Array(ecCount);
    for (let i = 0; i < data.length; i += 1) {
      const factor = data[i] ^ rem[0];
      for (let j = 0; j < ecCount - 1; j += 1) {
        rem[j] = rem[j + 1] ^ qrGfMul(gen[j + 1], factor);
      }
      rem[ecCount - 1] = qrGfMul(gen[ecCount], factor);
    }
    return rem;
  }

  // ISO/IEC 18004 Table 9 specs for Error Correction Level M (Versions 1..10, max 213 UTF-8 bytes)
  const QR_VERSION_SPECS_M = [
    null,
    { ver: 1, totalData: 16, ecPerBlock: 10, g1Blocks: 1, g1Data: 16, g2Blocks: 0, g2Data: 0, align: [] },
    { ver: 2, totalData: 28, ecPerBlock: 16, g1Blocks: 1, g1Data: 28, g2Blocks: 0, g2Data: 0, align: [6, 18] },
    { ver: 3, totalData: 44, ecPerBlock: 26, g1Blocks: 1, g1Data: 44, g2Blocks: 0, g2Data: 0, align: [6, 22] },
    { ver: 4, totalData: 64, ecPerBlock: 18, g1Blocks: 2, g1Data: 32, g2Blocks: 0, g2Data: 0, align: [6, 26] },
    { ver: 5, totalData: 86, ecPerBlock: 24, g1Blocks: 2, g1Data: 43, g2Blocks: 0, g2Data: 0, align: [6, 30] },
    { ver: 6, totalData: 108, ecPerBlock: 16, g1Blocks: 4, g1Data: 27, g2Blocks: 0, g2Data: 0, align: [6, 34] },
    { ver: 7, totalData: 124, ecPerBlock: 18, g1Blocks: 4, g1Data: 31, g2Blocks: 0, g2Data: 0, align: [6, 22, 38] },
    { ver: 8, totalData: 154, ecPerBlock: 22, g1Blocks: 2, g1Data: 38, g2Blocks: 2, g2Data: 39, align: [6, 24, 42] },
    { ver: 9, totalData: 182, ecPerBlock: 22, g1Blocks: 3, g1Data: 36, g2Blocks: 2, g2Data: 37, align: [6, 26, 46] },
    { ver: 10, totalData: 216, ecPerBlock: 26, g1Blocks: 4, g1Data: 43, g2Blocks: 1, g2Data: 44, align: [6, 28, 50] },
  ];

  function qrFormatBitsM(maskPattern) {
    // EC Level M = 0b00
    const data = maskPattern & 0x07;
    let rem = data << 10;
    for (let i = 4; i >= 0; i -= 1) {
      if (rem & (1 << (i + 10))) {
        rem ^= 0x537 << i;
      }
    }
    return ((data << 10) | rem) ^ 0x5412;
  }

  function qrVersionBits(version) {
    let rem = version << 12;
    for (let i = 5; i >= 0; i -= 1) {
      if (rem & (1 << (i + 12))) {
        rem ^= 0x1f25 << i;
      }
    }
    return (version << 12) | rem;
  }

  function qrMaskPredicate(mask, r, c) {
    switch (mask) {
      case 0: return (r + c) % 2 === 0;
      case 1: return r % 2 === 0;
      case 2: return c % 3 === 0;
      case 3: return (r + c) % 3 === 0;
      case 4: return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
      case 5: return ((r * c) % 2) + ((r * c) % 3) === 0;
      case 6: return (((r * c) % 2) + ((r * c) % 3)) % 2 === 0;
      case 7: return (((r + c) % 2) + ((r * c) % 3)) % 2 === 0;
      default: return false;
    }
  }

  function qrPenaltyScore(matrix) {
    const n = matrix.length;
    let score = 0;

    // Rule 1: 5+ consecutive same-color modules in row or column
    for (let r = 0; r < n; r += 1) {
      let runLen = 1;
      for (let c = 1; c < n; c += 1) {
        if (matrix[r][c] === matrix[r][c - 1]) {
          runLen += 1;
        } else {
          if (runLen >= 5) score += 3 + (runLen - 5);
          runLen = 1;
        }
      }
      if (runLen >= 5) score += 3 + (runLen - 5);
    }
    for (let c = 0; c < n; c += 1) {
      let runLen = 1;
      for (let r = 1; r < n; r += 1) {
        if (matrix[r][c] === matrix[r - 1][c]) {
          runLen += 1;
        } else {
          if (runLen >= 5) score += 3 + (runLen - 5);
          runLen = 1;
        }
      }
      if (runLen >= 5) score += 3 + (runLen - 5);
    }

    // Rule 2: 2x2 blocks of same color
    for (let r = 0; r < n - 1; r += 1) {
      for (let c = 0; c < n - 1; c += 1) {
        const v = matrix[r][c];
        if (v === matrix[r][c + 1] && v === matrix[r + 1][c] && v === matrix[r + 1][c + 1]) {
          score += 3;
        }
      }
    }

    // Rule 3: finder-like 1:1:3:1:1 with 4 light modules on either side
    const matchFinderLike = (arr) => {
      let hits = 0;
      for (let i = 0; i <= arr.length - 11; i += 1) {
        const p1 = arr[i] && !arr[i + 1] && arr[i + 2] && arr[i + 3] && arr[i + 4] && !arr[i + 5] && arr[i + 6] &&
          !arr[i + 7] && !arr[i + 8] && !arr[i + 9] && !arr[i + 10];
        const p2 = !arr[i] && !arr[i + 1] && !arr[i + 2] && !arr[i + 3] && arr[i + 4] && !arr[i + 5] && arr[i + 6] &&
          arr[i + 7] && arr[i + 8] && !arr[i + 9] && arr[i + 10];
        if (p1 || p2) hits += 40;
      }
      return hits;
    };
    for (let r = 0; r < n; r += 1) {
      score += matchFinderLike(matrix[r]);
    }
    const colBuf = new Array(n);
    for (let c = 0; c < n; c += 1) {
      for (let r = 0; r < n; r += 1) colBuf[r] = matrix[r][c];
      score += matchFinderLike(colBuf);
    }

    // Rule 4: dark/light balance
    let dark = 0;
    for (let r = 0; r < n; r += 1) {
      for (let c = 0; c < n; c += 1) {
        if (matrix[r][c]) dark += 1;
      }
    }
    const pct = (dark * 100) / (n * n);
    const k = Math.floor(Math.abs(pct - 50) / 5);
    score += k * 10;
    return score;
  }

  function encodeQrMatrix(text) {
    const bytes = new TextEncoder().encode(String(text || ''));
    let spec = null;
    for (let v = 1; v < QR_VERSION_SPECS_M.length; v += 1) {
      const candidate = QR_VERSION_SPECS_M[v];
      const countBits = v <= 9 ? 8 : 16;
      const neededBits = 4 + countBits + bytes.length * 8;
      if (neededBits <= candidate.totalData * 8) {
        spec = candidate;
        break;
      }
    }
    if (!spec) {
      throw new Error(`QR payload too long (${bytes.length} bytes, max 213)`);
    }

    // 1. Encode Byte-mode bitstream + terminator + padding
    const bits = [];
    const pushBits = (val, len) => {
      for (let i = len - 1; i >= 0; i -= 1) {
        bits.push((val >>> i) & 1);
      }
    };
    pushBits(0b0100, 4); // Byte mode
    pushBits(bytes.length, spec.ver <= 9 ? 8 : 16);
    for (let i = 0; i < bytes.length; i += 1) {
      pushBits(bytes[i], 8);
    }
    const totalDataBits = spec.totalData * 8;
    const terminator = Math.min(4, totalDataBits - bits.length);
    for (let i = 0; i < terminator; i += 1) bits.push(0);
    while (bits.length % 8 !== 0) bits.push(0);

    const dataCodewords = new Uint8Array(spec.totalData);
    let cwIdx = 0;
    for (let i = 0; i < bits.length; i += 8) {
      let b = 0;
      for (let j = 0; j < 8; j += 1) b = (b << 1) | bits[i + j];
      dataCodewords[cwIdx++] = b;
    }
    let padToggle = 0;
    while (cwIdx < spec.totalData) {
      dataCodewords[cwIdx++] = padToggle === 0 ? 0xec : 0x11;
      padToggle ^= 1;
    }

    // 2. Split into RS blocks & compute EC codewords
    const dataBlocks = [];
    const ecBlocks = [];
    let offset = 0;
    for (let i = 0; i < spec.g1Blocks; i += 1) {
      const blk = dataCodewords.subarray(offset, offset + spec.g1Data);
      offset += spec.g1Data;
      dataBlocks.push(blk);
      ecBlocks.push(qrRsComputeEc(blk, spec.ecPerBlock));
    }
    for (let i = 0; i < spec.g2Blocks; i += 1) {
      const blk = dataCodewords.subarray(offset, offset + spec.g2Data);
      offset += spec.g2Data;
      dataBlocks.push(blk);
      ecBlocks.push(qrRsComputeEc(blk, spec.ecPerBlock));
    }

    // 3. Interleave data & EC codewords
    const finalBytes = [];
    const maxDataLen = Math.max(spec.g1Data, spec.g2Data);
    for (let i = 0; i < maxDataLen; i += 1) {
      for (let b = 0; b < dataBlocks.length; b += 1) {
        if (i < dataBlocks[b].length) finalBytes.push(dataBlocks[b][i]);
      }
    }
    for (let i = 0; i < spec.ecPerBlock; i += 1) {
      for (let b = 0; b < ecBlocks.length; b += 1) {
        finalBytes.push(ecBlocks[b][i]);
      }
    }

    // 4. Construct base matrix with function patterns
    const size = spec.ver * 4 + 17;
    const base = Array.from({ length: size }, () => Array(size).fill(false));
    const isFunc = Array.from({ length: size }, () => Array(size).fill(false));
    const setFunc = (r, c, dark) => {
      if (r < 0 || r >= size || c < 0 || c >= size) return;
      base[r][c] = dark;
      isFunc[r][c] = true;
    };

    // Finder patterns + separators
    const drawFinder = (r0, c0) => {
      for (let dr = -1; dr <= 7; dr += 1) {
        for (let dc = -1; dc <= 7; dc += 1) {
          const r = r0 + dr;
          const c = c0 + dc;
          if (r < 0 || r >= size || c < 0 || c >= size) continue;
          const inBox = dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6;
          const border = dr === 0 || dr === 6 || dc === 0 || dc === 6;
          const core = dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4;
          setFunc(r, c, inBox && (border || core));
        }
      }
    };
    drawFinder(0, 0);
    drawFinder(0, size - 7);
    drawFinder(size - 7, 0);

    // Alignment patterns
    const centers = spec.align;
    for (let i = 0; i < centers.length; i += 1) {
      for (let j = 0; j < centers.length; j += 1) {
        const cr = centers[i];
        const cc = centers[j];
        if (isFunc[cr][cc]) continue;
        for (let dr = -2; dr <= 2; dr += 1) {
          for (let dc = -2; dc <= 2; dc += 1) {
            const dark = Math.max(Math.abs(dr), Math.abs(dc)) !== 1;
            setFunc(cr + dr, cc + dc, dark);
          }
        }
      }
    }

    // Timing patterns
    for (let i = 8; i < size - 8; i += 1) {
      if (!isFunc[6][i]) setFunc(6, i, i % 2 === 0);
      if (!isFunc[i][6]) setFunc(i, 6, i % 2 === 0);
    }

    // Reserve format info areas & dark module
    const drawFormatInfo = (mat, maskPattern) => {
      const fmt = qrFormatBitsM(maskPattern);
      // Copy 1
      for (let i = 0; i <= 5; i += 1) mat[8][i] = Boolean((fmt >>> (14 - i)) & 1);
      mat[8][7] = Boolean((fmt >>> 8) & 1);
      mat[8][8] = Boolean((fmt >>> 7) & 1);
      mat[7][8] = Boolean((fmt >>> 6) & 1);
      for (let i = 0; i <= 5; i += 1) mat[5 - i][8] = Boolean((fmt >>> (5 - i)) & 1);
      // Copy 2
      for (let i = 0; i <= 6; i += 1) mat[size - 1 - i][8] = Boolean((fmt >>> (14 - i)) & 1);
      for (let i = 0; i <= 7; i += 1) mat[8][size - 8 + i] = Boolean((fmt >>> (7 - i)) & 1);
      mat[size - 8][8] = true; // fixed dark module
    };
    for (let i = 0; i <= 8; i += 1) {
      if (!isFunc[8][i]) isFunc[8][i] = true;
      if (!isFunc[i][8]) isFunc[i][8] = true;
    }
    for (let i = 0; i < 8; i += 1) {
      isFunc[8][size - 1 - i] = true;
      isFunc[size - 1 - i][8] = true;
    }
    setFunc(size - 8, 8, true);

    // Version info for V7+
    if (spec.ver >= 7) {
      const vBits = qrVersionBits(spec.ver);
      for (let i = 0; i < 18; i += 1) {
        const dark = Boolean((vBits >>> i) & 1);
        const a = Math.floor(i / 3);
        const b = size - 11 + (i % 3);
        setFunc(b, a, dark);
        setFunc(a, b, dark);
      }
    }

    // 5. Place data bits in standard zig-zag order
    const allBits = [];
    for (let i = 0; i < finalBytes.length; i += 1) {
      const byte = finalBytes[i];
      for (let b = 7; b >= 0; b -= 1) allBits.push(Boolean((byte >>> b) & 1));
    }
    let bitIdx = 0;
    let upward = true;
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5; // skip vertical timing column
      for (let step = 0; step < size; step += 1) {
        const r = upward ? size - 1 - step : step;
        for (let dx = 0; dx < 2; dx += 1) {
          const c = right - dx;
          if (!isFunc[r][c]) {
            base[r][c] = bitIdx < allBits.length ? allBits[bitIdx++] : false;
          }
        }
      }
      upward = !upward;
    }

    // 6. Evaluate all 8 mask patterns & choose lowest penalty
    let bestMatrix = null;
    let bestScore = Infinity;
    let bestMask = 0;
    for (let mask = 0; mask < 8; mask += 1) {
      const candidate = base.map((row, r) =>
        row.map((val, c) => (isFunc[r][c] ? val : (qrMaskPredicate(mask, r, c) ? !val : val))),
      );
      drawFormatInfo(candidate, mask);
      const score = qrPenaltyScore(candidate);
      if (score < bestScore) {
        bestScore = score;
        bestMatrix = candidate;
        bestMask = mask;
      }
    }

    return { version: spec.ver, size, mask: bestMask, ecLevel: 'M', matrix: bestMatrix };
  }

  function factory(require) {
    const React = require('react');
    const h = React.createElement;
    const { useEffect, useRef, useState, useCallback } = React;

    const NS = 'tiana-remote';
    const PANEL_ID = 'tiana-remote';

    const zh = {
      panel: 'dsh-tiana-remote',
      title: 'dsh-tiana-remote',
      subtitleLocal: '零公网 IP 端到端加密远程访问管理',
      subtitleRemote: '当前正在通过端到端加密隧道访问远程主机',
      statusOnline: '在线运行中',
      statusPaused: '已暂停监听',
      statusUnconfigured: '尚未绑定',
      statusReconnecting: '正在重连 Relay…',
      statusConflictStopped: '宿主冲突已停机',
      statusCredentialsRevoked: '凭据已失效',
      statusLoading: '加载中…',
      statusAccessDenied: '访问受限',
      statusError: '加载失败',
      adminErrorTitle: '无法加载主机管理状态',
      adminAccessDeniedTitle: '主机管理接口访问受限',
      adminErrorHint: '请确认当前浏览器通过本机或受信任的局域网／Tailnet 地址访问 DSH（且已配置 --trusted-host 并具备有效的本机所有者会话）。',
      retry: '重试',
      loadingOverview: '正在加载 dsh-tiana-remote 状态…',
      toggleLabel: '启用远程访问',
      remoteUrl: '托管访问地址',
      copy: '复制',
      copied: '已复制',
      open: '打开',
      qrCode: '扫码打开',
      qrTitle: '扫码访问远程工作台',
      qrHint: '使用手机或平板相机扫描此标准二维码（二维码不含密钥，打开后粘贴配对密钥解锁）。',
      close: '关闭',
      cancel: '取消',
      e2eeTitle: '端到端加密配对密钥（E2EE）',
      e2eeFingerprint: '密钥指纹',
      revealKey: '显示密钥',
      hideKey: '隐藏密钥',
      copyKey: '复制配对密钥',
      rotateKey: '轮换密钥',
      rotateConfirmTitle: '确认轮换端到端配对密钥？',
      rotateConfirmBody: '轮换后，所有已连接的远端浏览器会话将被立即断开（4001 key_rotated），需要使用新密钥重新解锁。',
      rotateConfirmBtn: '确认轮换',
      sessionsTitle: '活跃远端会话与实例凭据',
      sessionsEmpty: '当前没有活跃的远端浏览器会话',
      disconnect: '断开',
      disconnectAll: '断开全部',
      settingsTitle: '主机、绑定与网络设置',
      hostName: '主机显示名',
      p2pToggle: '启用 WebRTC P2P 直连优先',
      stunUrls: 'STUN 服务器（逗号分隔）',
      conflictBannerTitle: '检测到重复的 DSH 主机进程冲突',
      conflictBannerOwnedByOther: '另一台本地 DSH 进程正在占用 Relay 连接，本进程已暂停重复建连以避免断线循环。请关闭多余的 DSH 实例。',
      conflictBannerRelayKicked: '当前 Relay 连接被同 host_id 的另一个主机实例顶替，已启用退避重连。请检查并停止本机多余的 DSH 进程。',
      conflictBannerTerminal: '已有另一个宿主实例在线，本机已立即停止自动重连以防互踢。请先停止旧实例后再点击「重试连接」，或在确认旧实例失联时选择「强制接管」。',
      revokedBannerTitle: '连接凭据已失效（可能已被其他宿主接管或解绑）',
      revokedBannerBody: 'Relay 拒绝了当前主机凭据（HTTP 403），本机已停止自动重连。请重新绑定，或点击「强制接管」轮换 registrationKey 重新接管此云端应用。',
      retryConnectBtn: '重试连接',
      retryingConnect: '正在重连…',
      forceTakeoverBtn: '强制接管',
      forceTakeoverConfirmTitle: '确认强制接管云端 Relay？',
      forceTakeoverConfirmBody: '强制接管将强制轮换 registrationKey 并写入云端新策略，使原在线宿主的旧凭据立即失效（旧宿主收到 403 后将自动停机）。请确认旧宿主已停止或失联后再继续。',
      forceTakeoverConfirmBtn: '确认强制接管',
      activeHostLabel: '当前在线宿主',
      saveSettings: '保存设置',
      resetDraft: '放弃未保存更改',
      saving: '保存中…',
      saved: '已保存',
      repairTitle: '同步/修复云端访问页',
      repairBtn: '同步/修复云端访问页',
      repairDesc: '升级本机插件后，或云端访问页打不开、连接异常时使用。会将当前版本的远端页面与连接配置重新同步到云端应用，不影响已有配对密钥和本机数据。',
      repairing: '正在同步…',
      repaired: '云端访问页已同步',
      tokenExpiry: 'Function 实例 Token 到期',
      tokenRenewing: '续期中…',
      tokenRenewed: '实例 Token 已续期（30 天有效）',
      renewToken: '立即续期',
      remoteChannel: '当前连接通道',
      remoteP2p: 'WebRTC P2P 直连',
      remoteRelay: 'Tiana Relay 加密中继',
      remoteReconnecting: '正在重连…',
      remoteRtt: '往返延迟 (RTT)',
      remoteSecurityNote: '安全边界说明：当前处于远端隧道受限视图。配对密钥查看/轮换与主机管理接口仅限本机访问，远端隧道严格返回 403 拦截。',
      clearCacheTitle: '清除缓存并刷新',
      clearCacheBtn: '清除缓存并刷新',
      clearCacheDesc: '当本机升级了 DSH 或某个插件后，如果远端界面仍显示旧版本或出现异常，可点击此项清除当前浏览器缓存的前端资源并重新加载最新页面（不影响本机数据，也不会清除已保存的配对密钥）。',
      lockForgetTitle: '解除此设备绑定',
      lockForgetBtn: '解除此设备绑定',
      lockForgetDesc: '仅清除当前设备／浏览器中保存的配对密钥并断开连接；Tiana 云端应用与本机电脑的关联仍然存在，仍可从其他设备或重新输入配对密钥登录。如需解除或更换云端应用与主机的绑定，请在本机电脑直接打开 DSH 的「dsh-tiana-remote」面板操作（受安全边界限制，主机绑定与密钥管理仅限本机访问）。',
      onboardTitle: '绑定或新建云端 dsh-tiana-remote 应用',
      onboardBindTab: '绑定已有 Tiana 应用',
      onboardCreateTab: '在当前空间新建 dsh-tiana-remote 应用',
      webIdLabel: 'Tiana Web 应用 ID（12 位，如 abc123456789）',
      webNameLabel: '新建应用名称',
      rebindForceLabel: '若该应用已绑定其他电脑，强制换绑到本机',
      bindSubmitBtn: '立即免编译绑定',
      createSubmitBtn: '立即创建并配置',
      cloudBindingTitle: '云端应用绑定',
      unbindBtn: '解除绑定',
      unbinding: '正在解除绑定…',
      unbindDesc: '解除后本机将停止远端隧道并回到未绑定状态，不会删除云端应用，随时可重新绑定或新建应用。',
      unbindConfirmTitle: '确认解除云端应用绑定？',
      unbindConfirmBody: '解除绑定将立即停止远端隧道、断开所有在线远端会话，并清空本机保存的绑定信息与配对密钥。不会删除云端 Tiana Web 应用与 Relay Function，之后随时可重新绑定原应用、绑定其他应用或新建应用。',
      unbindConfirmBtn: '确认解除绑定',
      unbindDone: '已解除与云端应用的绑定（原云端应用已保留）',
      unbindDoneCloudWarn: '本机已解除绑定，云端策略因离线或权限暂未同步清理，不影响后续重绑',
      lastBoundLabel: '上次绑定',
      rebindLastBoundBtn: '填入并重绑',
      provisionRunning: '正在执行配置任务…',
      provisionDone: '配置已完成',
    };

    const en = {
      panel: 'dsh-tiana-remote',
      title: 'dsh-tiana-remote',
      subtitleLocal: 'End-to-end encrypted remote access for this DSH host',
      subtitleRemote: 'Connected to your local DSH host via E2EE tunnel',
      statusOnline: 'Online',
      statusPaused: 'Paused',
      statusUnconfigured: 'Not Bound',
      statusReconnecting: 'Reconnecting…',
      statusConflictStopped: 'Stopped (Host Conflict)',
      statusCredentialsRevoked: 'Credentials Revoked',
      statusLoading: 'Loading…',
      statusAccessDenied: 'Access Denied',
      statusError: 'Error',
      adminErrorTitle: 'Unable to load host management status',
      adminAccessDeniedTitle: 'Host admin API access denied',
      adminErrorHint: 'Verify you are accessing DSH over loopback or a private LAN/Tailnet address configured via --trusted-host with an active owner session.',
      retry: 'Retry',
      loadingOverview: 'Loading dsh-tiana-remote status…',
      toggleLabel: 'Enable Remote Access',
      remoteUrl: 'Hosted Remote URL',
      copy: 'Copy',
      copied: 'Copied',
      open: 'Open',
      qrCode: 'QR Code',
      qrTitle: 'Open via QR Code',
      qrHint: 'Scan this standard QR code with your phone camera (pairing key is never embedded in the URL).',
      close: 'Close',
      cancel: 'Cancel',
      e2eeTitle: 'End-to-End Pairing Key (E2EE)',
      e2eeFingerprint: 'Key Fingerprint',
      revealKey: 'Reveal',
      hideKey: 'Hide',
      copyKey: 'Copy Pairing Key',
      rotateKey: 'Rotate Key',
      rotateConfirmTitle: 'Rotate E2EE pairing key?',
      rotateConfirmBody: 'All active remote sessions will be immediately disconnected (4001 key_rotated) and must unlock with the new key.',
      rotateConfirmBtn: 'Confirm Rotate',
      sessionsTitle: 'Active Remote Sessions & Instance Token',
      sessionsEmpty: 'No active remote sessions',
      disconnect: 'Disconnect',
      disconnectAll: 'Disconnect All',
      settingsTitle: 'Host, Binding & Network Settings',
      hostName: 'Host Display Name',
      p2pToggle: 'Prefer WebRTC P2P Direct Connection',
      stunUrls: 'STUN Servers (comma-separated)',
      conflictBannerTitle: 'Duplicate DSH Host Process Conflict Detected',
      conflictBannerOwnedByOther: 'Another live DSH process currently owns the Relay bridge. This instance paused duplicate connection attempts to prevent reconnect loops. Stop extra DSH processes.',
      conflictBannerRelayKicked: 'The Relay connection was replaced by another host using the same host_id. Backoff is active; stop duplicate DSH instances to stabilize.',
      conflictBannerTerminal: 'Another host instance is already connected to this Relay. Auto-reconnect has been stopped to prevent kick loops. Stop the existing host and click Retry Connection, or choose Force Takeover if the old machine is unreachable.',
      revokedBannerTitle: 'Host Credentials Revoked (Taken Over or Unbound)',
      revokedBannerBody: 'The Relay rejected this host’s credentials (HTTP 403) and auto-reconnect has stopped. Rebind this host or choose Force Takeover to rotate registrationKey and reclaim the app.',
      retryConnectBtn: 'Retry Connection',
      retryingConnect: 'Reconnecting…',
      forceTakeoverBtn: 'Force Takeover',
      forceTakeoverConfirmTitle: 'Confirm Force Takeover?',
      forceTakeoverConfirmBody: 'Force takeover rotates registrationKey and overwrites the cloud Relay policy so the previous host’s credentials immediately return 403 and stop. Continue only if the old host is offline/unreachable or you intend to replace it.',
      forceTakeoverConfirmBtn: 'Confirm Force Takeover',
      activeHostLabel: 'Active Online Host',
      saveSettings: 'Save Settings',
      resetDraft: 'Discard Unsaved Edits',
      saving: 'Saving…',
      saved: 'Saved',
      repairTitle: 'Sync / Repair Cloud Page',
      repairBtn: 'Sync / Repair Cloud Page',
      repairDesc: 'Use after upgrading this plugin or if the cloud page fails to load or connect. Re-syncs the latest remote page and connection settings to your cloud app without changing your pairing key or local data.',
      repairing: 'Syncing…',
      repaired: 'Cloud page synced',
      tokenExpiry: 'Function Token Expiry',
      tokenRenewing: 'Renewing…',
      tokenRenewed: 'Function token renewed (30 days)',
      renewToken: 'Renew Now',
      remoteChannel: 'Active Transport Channel',
      remoteP2p: 'WebRTC P2P Direct',
      remoteRelay: 'Tiana Encrypted Relay',
      remoteReconnecting: 'Reconnecting…',
      remoteRtt: 'Round-Trip Latency (RTT)',
      remoteSecurityNote: 'Security Isolation: Pairing keys and host admin APIs are strictly blocked (403) over the remote tunnel.',
      clearCacheTitle: 'Clear Cache & Reload',
      clearCacheBtn: 'Clear Cache & Reload',
      clearCacheDesc: 'If the remote interface still shows an older version or behaves unexpectedly after upgrading DSH or a plugin on your host, clear this browser’s cached frontend assets and reload the latest UI. Your local host data and saved pairing key will not be affected.',
      lockForgetTitle: 'Unbind This Device',
      lockForgetBtn: 'Unbind This Device',
      lockForgetDesc: 'Clears the saved pairing key on this device/browser only and disconnects. The link between your Tiana cloud app and host computer remains active, so you can still sign in from other devices or re-enter the pairing key. To unbind or switch the cloud app on your host, open the "dsh-tiana-remote" panel directly on your host computer (host binding and key management are restricted to local access for security isolation).',
      onboardTitle: 'Bind or Create a Tiana dsh-tiana-remote App',
      onboardBindTab: 'Bind Existing Tiana App',
      onboardCreateTab: 'Create New dsh-tiana-remote App',
      webIdLabel: 'Tiana Web App ID (12 chars, e.g. abc123456789)',
      webNameLabel: 'New Web App Name',
      rebindForceLabel: 'Force rebind to this machine if bound to another host',
      bindSubmitBtn: 'Bind Now (Zero Recompile)',
      createSubmitBtn: 'Create & Provision',
      cloudBindingTitle: 'Cloud App Binding',
      unbindBtn: 'Unbind Cloud App',
      unbinding: 'Unbinding…',
      unbindDesc: 'Stops the remote tunnel on this host and returns to the unbound state without deleting your cloud app. You can rebind or create a new app anytime.',
      unbindConfirmTitle: 'Unbind this cloud app?',
      unbindConfirmBody: 'Unbinding immediately stops the remote tunnel, disconnects all active remote sessions, and clears local binding credentials and pairing keys. Your cloud Tiana Web app and Relay Function will NOT be deleted, and you can rebind or create a new app anytime.',
      unbindConfirmBtn: 'Confirm Unbind',
      unbindDone: 'Unbound from cloud app (your cloud app has been preserved)',
      unbindDoneCloudWarn: 'Local host unbound; cloud policy cleanup was skipped (offline or permissions), which will not affect rebinding',
      lastBoundLabel: 'Last Bound',
      rebindLastBoundBtn: 'Rebind Now',
      provisionRunning: 'Provisioning in progress…',
      provisionDone: 'Provisioning completed',
    };

    const STYLES = `
      .dshr-root {
        box-sizing: border-box;
        height: 100%;
        overflow: auto;
        padding: 24px;
        color: var(--dsw-alias-label-primary, #e5edf9);
        background: var(--dsw-alias-bg-layer-1, transparent);
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      }
      .dshr-wrap { max-width: 880px; margin: 0 auto; display: grid; gap: 16px; }
      .dshr-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
      .dshr-title { margin: 0; font-size: 20px; font-weight: 600; color: var(--dsw-alias-label-primary, inherit); }
      .dshr-sub { margin: 4px 0 0; font-size: 13px; color: var(--dsw-alias-label-secondary, #94a3b8); }
      .dshr-card {
        background: var(--dsw-alias-bg-layer-2, rgba(30, 41, 59, 0.55));
        border: 1px solid var(--dsw-alias-border-l1, rgba(148, 163, 184, 0.22));
        border-radius: 12px;
        padding: 18px 20px;
        display: grid;
        gap: 14px;
      }
      .dshr-card-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
      .dshr-card-title { margin: 0; font-size: 15px; font-weight: 600; }
      .dshr-row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
      .dshr-tabs { display: flex; gap: 8px; flex-wrap: wrap; }
      .dshr-tab {
        padding: 6px 12px; border-radius: 8px; font-size: 13px; font-weight: 500; cursor: pointer;
        border: 1px solid var(--dsw-alias-border-l1, rgba(148, 163, 184, 0.3));
        background: transparent; color: var(--dsw-alias-label-secondary, #94a3b8);
      }
      .dshr-tab[aria-selected="true"] {
        background: var(--dsw-alias-brand-primary, #2563eb);
        border-color: transparent;
        color: var(--dsw-alias-label-primary-foreground, #ffffff);
      }
      .dshr-badge {
        display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 999px;
        font-size: 12px; font-weight: 500;
        background: var(--dsw-alias-bg-layer-3, rgba(15, 23, 42, 0.6));
        border: 1px solid var(--dsw-alias-border-l1, rgba(148, 163, 184, 0.25));
      }
      .dshr-dot { width: 8px; height: 8px; border-radius: 50%; background: #94a3b8; }
      .dshr-dot.is-online { background: #22c55e; box-shadow: 0 0 0 3px rgba(34, 197, 94, 0.25); }
      .dshr-dot.is-warn { background: #f59e0b; }
      .dshr-dot.is-error { background: var(--dsw-alias-state-error-primary, #ef4444); box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.25); }
      .dshr-mono {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 13px; padding: 8px 12px; border-radius: 8px; flex: 1; min-width: 200px;
        background: var(--dsw-alias-bg-layer-1, rgba(15, 23, 42, 0.7));
        border: 1px solid var(--dsw-alias-border-l1, rgba(148, 163, 184, 0.25));
        color: var(--dsw-alias-label-primary, inherit);
        overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
      }
      .dshr-logs {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 12px; line-height: 1.5; padding: 10px 12px; border-radius: 8px;
        max-height: 160px; overflow: auto; white-space: pre-wrap; margin: 0;
        background: var(--dsw-alias-bg-layer-1, rgba(15, 23, 42, 0.75));
        border: 1px solid var(--dsw-alias-border-l1, rgba(148, 163, 184, 0.25));
      }
      .dshr-btn {
        display: inline-flex; align-items: center; justify-content: center; gap: 6px;
        padding: 7px 13px; border-radius: 8px; font-size: 13px; font-weight: 500; cursor: pointer;
        border: 1px solid var(--dsw-alias-border-l1, rgba(148, 163, 184, 0.3));
        background: var(--dsw-alias-bg-layer-3, rgba(30, 41, 59, 0.9));
        color: var(--dsw-alias-label-primary, #f8fafc);
      }
      .dshr-btn:hover:not(:disabled) { filter: brightness(1.08); }
      .dshr-btn:disabled { opacity: 0.5; cursor: not-allowed; }
      .dshr-root .dshr-btn-primary,
      .dshr-root a.dshr-btn-primary,
      .dshr-root a.dshr-btn-primary:visited,
      .dshr-root a.dshr-btn-primary:hover {
        background: var(--dsw-alias-brand-primary, #2563eb);
        border-color: transparent;
        color: var(--dsw-alias-label-primary-foreground, #ffffff);
      }
      .dshr-btn-danger {
        background: rgba(220, 38, 38, 0.16);
        border-color: rgba(248, 113, 113, 0.45);
        color: var(--dsw-alias-state-error-primary, #f87171);
      }
      .dshr-input {
        box-sizing: border-box; width: 100%; padding: 8px 12px; border-radius: 8px; font-size: 13px;
        border: 1px solid var(--dsw-alias-border-l1, rgba(148, 163, 184, 0.3));
        background: var(--dsw-alias-bg-layer-1, rgba(15, 23, 42, 0.7));
        color: var(--dsw-alias-label-primary, inherit);
      }
      .dshr-field { display: grid; gap: 6px; font-size: 13px; }
      .dshr-label { color: var(--dsw-alias-label-secondary, #94a3b8); font-size: 12px; }
      .dshr-session-item {
        display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap;
        padding: 10px 12px; border-radius: 8px;
        background: var(--dsw-alias-bg-layer-1, rgba(15, 23, 42, 0.45));
        border: 1px solid var(--dsw-alias-border-l1, rgba(148, 163, 184, 0.18));
      }
      .dshr-action-list { display: grid; gap: 10px; }
      .dshr-action-item {
        display: flex; align-items: flex-start; justify-content: space-between; gap: 14px; flex-wrap: wrap;
        padding: 12px 14px; border-radius: 10px;
        background: var(--dsw-alias-bg-layer-1, rgba(15, 23, 42, 0.45));
        border: 1px solid var(--dsw-alias-border-l1, rgba(148, 163, 184, 0.18));
      }
      .dshr-action-copy { flex: 1 1 260px; min-width: 0; display: grid; gap: 4px; }
      .dshr-action-title { font-size: 13px; font-weight: 600; color: var(--dsw-alias-label-primary, inherit); }
      .dshr-action-desc { font-size: 12px; line-height: 1.55; color: var(--dsw-alias-label-secondary, #94a3b8); }
      .dshr-action-control { flex: 0 0 auto; align-self: center; }
      .dshr-divider { height: 1px; background: var(--dsw-alias-border-l1, rgba(148, 163, 184, 0.18)); }
      .dshr-notice {
        padding: 12px 14px; border-radius: 10px; font-size: 13px; line-height: 1.5;
        background: rgba(59, 130, 246, 0.12); border: 1px solid rgba(96, 165, 250, 0.35);
      }
      .dshr-warn {
        padding: 12px 14px; border-radius: 10px; font-size: 13px; line-height: 1.5;
        background: rgba(245, 158, 11, 0.14); border: 1px solid rgba(251, 191, 36, 0.45);
      }
      .dshr-err {
        padding: 10px 12px; border-radius: 8px; font-size: 13px; line-height: 1.45;
        background: rgba(220, 38, 38, 0.14);
        border: 1px solid rgba(248, 113, 113, 0.45);
        color: var(--dsw-alias-state-error-primary, #f87171);
      }
      .dshr-switch { display: inline-flex; align-items: center; gap: 8px; cursor: pointer; font-size: 13px; font-weight: 500; }
      dialog.dshr-dialog {
        padding: 20px 22px; border-radius: 14px; max-width: 420px; width: calc(100vw - 32px);
        background: var(--dsw-alias-bg-layer-2, #1e293b);
        color: var(--dsw-alias-label-primary, #f8fafc);
        border: 1px solid var(--dsw-alias-border-l1, rgba(148, 163, 184, 0.3));
        box-shadow: 0 24px 60px rgba(0, 0, 0, 0.45);
      }
      dialog.dshr-dialog:modal { overscroll-behavior: contain; }
      dialog.dshr-dialog::backdrop {
        background: rgba(2, 6, 23, 0.65);
        overflow: hidden;
        overscroll-behavior: contain;
      }
    `;

    function ensureStyleTag() {
      if (typeof document === 'undefined') return;
      if (document.getElementById('dsh-remote-panel-styles')) return;
      const el = document.createElement('style');
      el.id = 'dsh-remote-panel-styles';
      el.textContent = STYLES;
      document.head.appendChild(el);
    }

    /**
     * Render a genuine ISO/IEC 18004 scannable QR Code SVG (quiet zone = 4 modules, EC Level M).
     */
    function buildQrSvgData(text) {
      const qr = encodeQrMatrix(text);
      const quiet = 4;
      const total = qr.size + quiet * 2;
      const parts = [];
      for (let r = 0; r < qr.size; r += 1) {
        for (let c = 0; c < qr.size; c += 1) {
          if (qr.matrix[r][c]) {
            parts.push(`M${c + quiet},${r + quiet}h1v1h-1z`);
          }
        }
      }
      return h('svg', {
        viewBox: `0 0 ${total} ${total}`,
        width: 220,
        height: 220,
        shapeRendering: 'crispEdges',
        role: 'img',
        'aria-label': text,
        'data-qr-version': String(qr.version),
        'data-qr-size': String(qr.size),
        'data-qr-ec': qr.ecLevel,
        style: { background: '#ffffff', borderRadius: 10, display: 'block', margin: '0 auto' },
      },
        h('rect', { x: 0, y: 0, width: total, height: total, fill: '#ffffff' }),
        h('path', { d: parts.join(''), fill: '#000000' }),
      );
    }

    function RemoteIcon({ size = 18 } = {}) {
      return h('svg', {
        width: size, height: size, viewBox: '0 0 24 24', fill: 'none',
        stroke: 'currentColor', strokeLinecap: 'round', strokeLinejoin: 'round',
      },
        h('path', { d: 'M4.3 6.2a9.6 9.6 0 0 0 0 11.6M19.7 6.2a9.6 9.6 0 0 1 0 11.6', strokeWidth: 1.5, opacity: 0.72 }),
        h('path', { d: 'M6.4 8.2a6.6 6.6 0 0 0 0 7.6M17.6 8.2a6.6 6.6 0 0 1 0 7.6', strokeWidth: 1.45, opacity: 0.9 }),
        h('path', { d: 'M10.7 13.6 11.55 9.6a.46.46 0 0 1 .9 0l.85 4M10.4 13.5l.6.5h2l.6-.5', strokeWidth: 1.55 }),
        h('path', { d: 'M10.9 10.9 9.4 9.6V7.5l.9-1.1M13.1 10.9l1.5-1.3V7.5L14 6.4M10.5 11.9 8.6 11.2V9.3M13.5 11.9l1.9-.7V9.3M10.4 12.9 8.6 13.6v2.1M13.6 12.9l1.8.7v2.1M10.8 13.8 9.4 15.1v2l.9 1.1M13.2 13.8l1.4 1.3v2l-.9 1.1', strokeWidth: 1.35 }),
      );
    }

    function formatDuration(ms) {
      const sec = Math.max(0, Math.floor((ms || 0) / 1000));
      if (sec < 60) return `${sec}s`;
      const min = Math.floor(sec / 60);
      if (min < 60) return `${min}m ${sec % 60}s`;
      return `${Math.floor(min / 60)}h ${min % 60}m`;
    }

    function formatTokenExpiry(expiresAtSec, isZh) {
      if (!expiresAtSec || !Number.isFinite(expiresAtSec)) return '—';
      const remainingSec = Math.floor(expiresAtSec - Date.now() / 1000);
      if (remainingSec <= 0) {
        return isZh ? '已过期（请立即续期）' : 'Expired (renew now)';
      }
      const days = Math.ceil(remainingSec / 86400);
      return isZh
        ? `剩余 ${days} 天（到期前 7 天自动续期）`
        : `${days}d remaining (auto-renews < 7d)`;
    }

    function pickStrings(locale) {
      const isZh = typeof locale === 'string'
        ? locale.toLowerCase().startsWith('zh')
        : (typeof navigator !== 'undefined' && String(navigator.language || '').toLowerCase().startsWith('zh'));
      return { strings: isZh ? zh : en, isZh };
    }

    function TianaRemotePanel({ t: boundT, forceMode } = {}) {
      ensureStyleTag();
      const { strings, isZh } = pickStrings();
      const t = (key) => (typeof boundT === 'function' ? boundT(key) : strings[key] || key);
      const isRemote = forceMode
        ? forceMode === 'remote'
        : Boolean(globalThis.__DSH_REMOTE_SHELL__?.isRemote || globalThis.__DSH_TRANSPORT__?.ownsHost);

      const [overview, setOverview] = useState(null);
      const [adminLoading, setAdminLoading] = useState(() => !isRemote);
      const [adminLoadError, setAdminLoadError] = useState(null);
      const [publicStatus, setPublicStatus] = useState(null);
      const [shellSnap, setShellSnap] = useState(() => globalThis.__DSH_REMOTE_SHELL__?.getStatusSnapshot?.() || null);
      const [revealedKey, setRevealedKey] = useState('');
      const [copiedTag, setCopiedTag] = useState('');
      const [busy, setBusy] = useState('');
      const [toast, setToast] = useState('');

      // Draft fields protected from 4s background poll overwrite while dirty
      const [hostNameDraft, setHostNameDraft] = useState('');
      const [p2pDraft, setP2pDraft] = useState(true);
      const [stunDraft, setStunDraft] = useState('');
      const settingsDirtyRef = useRef(false);
      const [settingsDirty, setSettingsDirty] = useState(false);

      // Provision / Onboarding / Unbind state
      const [onboardTab, setOnboardTab] = useState('bind');
      const [bindWebId, setBindWebId] = useState('');
      const [bindHostName, setBindHostName] = useState('');
      const bindHostNameDirtyRef = useRef(false);
      const [bindForceRebind, setBindForceRebind] = useState(false);
      const [createWebName, setCreateWebName] = useState('dsh-tiana-remote');
      const [provisionStatus, setProvisionStatus] = useState(null);
      const [lastProvisionPayload, setLastProvisionPayload] = useState(null);
      const [pendingForceTakeover, setPendingForceTakeover] = useState(null);

      const rotateDialogRef = useRef(null);
      const qrDialogRef = useRef(null);
      const forceTakeoverDialogRef = useRef(null);
      const unbindDialogRef = useRef(null);

      const hydrateDraftsFromOverview = useCallback((data) => {
        if (!data) return;
        setHostNameDraft(data.host?.hostName || '');
        setP2pDraft(data.network?.p2pEnabled !== false);
        setStunDraft((data.network?.stunUrls || []).join(','));
        if (!bindHostNameDirtyRef.current && data.host?.hostName) {
          setBindHostName(data.host.hostName);
        }
      }, []);

      const markDirty = () => {
        settingsDirtyRef.current = true;
        setSettingsDirty(true);
      };

      const fetchState = useCallback(async () => {
        try {
          if (isRemote) {
            const resp = await fetch('/api/tiana-remote/public-status', { cache: 'no-store' });
            if (resp.ok) {
              setPublicStatus(await resp.json());
            }
            const snap = globalThis.__DSH_REMOTE_SHELL__?.getStatusSnapshot?.();
            if (snap) setShellSnap(snap);
          } else {
            const resp = await fetch('/api/tiana-remote/admin/overview', { cache: 'no-store' });
            if (resp.ok) {
              const data = await resp.json();
              setOverview(data);
              setAdminLoadError(null);
              // NEVER overwrite user's in-progress form edits during background polling
              if (!settingsDirtyRef.current) {
                hydrateDraftsFromOverview(data);
              }
            } else {
              let errMessage = '';
              try {
                const errBody = await resp.json();
                if (errBody && typeof errBody.error === 'string') {
                  errMessage = errBody.error;
                }
              } catch {
                try {
                  errMessage = (await resp.text()).trim();
                } catch {
                  // ignore body parse failures
                }
              }
              setAdminLoadError({
                status: resp.status,
                message: errMessage || resp.statusText || `HTTP ${resp.status}`,
              });
            }
          }
        } catch (err) {
          if (!isRemote) {
            setAdminLoadError({
              status: 0,
              message: err instanceof Error ? err.message : String(err || 'Network error'),
            });
          }
        } finally {
          if (!isRemote) {
            setAdminLoading(false);
          }
        }
      }, [isRemote, hydrateDraftsFromOverview]);

      const pollProvisionStatus = useCallback(async () => {
        if (isRemote) return;
        try {
          const resp = await fetch('/api/tiana-remote/admin/provision-status', { cache: 'no-store' });
          if (resp.ok) {
            const st = await resp.json();
            setProvisionStatus(st);
            if (!st.running && st.step === 'done') {
              await fetchState();
            }
          }
        } catch {
          // ignore
        }
      }, [isRemote, fetchState]);

      useEffect(() => {
        void fetchState();
        const timer = setInterval(() => void fetchState(), 4000);
        let unsub = null;
        if (isRemote && typeof globalThis.__DSH_REMOTE_SHELL__?.subscribe === 'function') {
          unsub = globalThis.__DSH_REMOTE_SHELL__.subscribe((snap) => setShellSnap(snap));
        }
        return () => {
          clearInterval(timer);
          if (typeof unsub === 'function') unsub();
        };
      }, [fetchState, isRemote]);

      useEffect(() => {
        if (!provisionStatus?.running) return undefined;
        const timer = setInterval(() => void pollProvisionStatus(), 1000);
        return () => clearInterval(timer);
      }, [provisionStatus?.running, pollProvisionStatus]);

      const copyText = async (tag, value) => {
        try {
          await navigator.clipboard.writeText(value);
          setCopiedTag(tag);
          setTimeout(() => setCopiedTag(''), 1800);
        } catch {
          setToast('Clipboard write unavailable');
        }
      };

      // ---- Remote Restricted Session View ----
      if (isRemote) {
        const mode = shellSnap?.transportState || shellSnap?.transport || 'Relay';
        const isP2p = String(mode).toLowerCase() === 'p2p';
        const isReconnecting = String(mode).toLowerCase().includes('reconnect') || String(mode).includes('重连');
        const rttText = typeof shellSnap?.rttMs === 'number' ? `${shellSnap.rttMs} ms` : '—';
        const hostName = shellSnap?.hostName || publicStatus?.hostName || publicStatus?.hostId || 'Local DSH';
        const fingerprint = shellSnap?.fingerprint || publicStatus?.e2eeFingerprint || '—';

        return h('div', { className: 'dshr-root', 'data-dshr-mode': 'remote' },
          h('div', { className: 'dshr-wrap' },
            h('div', { className: 'dshr-header' },
              h('div', null,
                h('h2', { className: 'dshr-title' }, t('title')),
                h('p', { className: 'dshr-sub' }, t('subtitleRemote')),
              ),
              h('span', { className: 'dshr-badge' },
                h('span', { className: `dshr-dot ${isReconnecting ? 'is-warn' : 'is-online'}` }),
                isReconnecting ? t('remoteReconnecting') : (isP2p ? t('remoteP2p') : t('remoteRelay')),
              ),
            ),
            toast && h('div', { className: 'dshr-notice', role: 'status' }, toast),
            h('div', { className: 'dshr-card' },
              h('div', { className: 'dshr-card-head' },
                h('h3', { className: 'dshr-card-title' }, `${t('remoteChannel')} · ${hostName}`),
                h('span', { className: 'dshr-label' }, `${t('remoteRtt')}: ${rttText}`),
              ),
              h('div', { className: 'dshr-row' },
                h('span', { className: 'dshr-badge' }, `${t('e2eeFingerprint')}: ${fingerprint}`),
                h('span', { className: 'dshr-badge' }, isP2p ? t('remoteP2p') : t('remoteRelay')),
              ),
              h('div', { className: 'dshr-notice' }, t('remoteSecurityNote')),
              h('div', { className: 'dshr-action-list', id: 'dshr-remote-actions' },
                h('div', { className: 'dshr-action-item', id: 'dshr-remote-action-clear-cache' },
                  h('div', { className: 'dshr-action-copy' },
                    h('div', { className: 'dshr-action-title' }, t('clearCacheTitle')),
                    h('div', { className: 'dshr-action-desc', id: 'dshr-remote-clear-cache-desc' }, t('clearCacheDesc')),
                  ),
                  h('div', { className: 'dshr-action-control' },
                    h('button', {
                      type: 'button',
                      className: 'dshr-btn',
                      id: 'dshr-remote-clear-cache',
                      'aria-describedby': 'dshr-remote-clear-cache-desc',
                      onClick: () => void globalThis.__DSH_REMOTE_SHELL__?.clearFrontendCache?.(),
                    }, t('clearCacheBtn')),
                  ),
                ),
                h('div', { className: 'dshr-action-item', id: 'dshr-remote-action-unbind-device' },
                  h('div', { className: 'dshr-action-copy' },
                    h('div', { className: 'dshr-action-title' }, t('lockForgetTitle')),
                    h('div', { className: 'dshr-action-desc', id: 'dshr-remote-lock-forget-desc' }, t('lockForgetDesc')),
                  ),
                  h('div', { className: 'dshr-action-control' },
                    h('button', {
                      type: 'button',
                      className: 'dshr-btn dshr-btn-danger',
                      id: 'dshr-remote-lock-forget',
                      'aria-describedby': 'dshr-remote-lock-forget-desc',
                      onClick: () => void globalThis.__DSH_REMOTE_SHELL__?.lockAndForget?.(),
                    }, t('lockForgetBtn')),
                  ),
                ),
              ),
            ),
          ),
        );
      }

      // ---- Local Host Full Management View ----
      const configured = Boolean(overview?.configured);
      const enabled = Boolean(overview?.enabled);
      const relayConnected = Boolean(overview?.bridge?.relayConnected);
      const sessions = overview?.bridge?.sessions || [];
      const endpoint = overview?.web?.endpoint || '';
      const tokenExpiresAt = overview?.function?.expiresAt;
      const bridgeConflict = overview?.bridgeConflict || null;
      const terminalState = overview?.bridge?.terminalState || null;
      const isTerminalConflict = terminalState === 'conflict_active_host';
      const isCredentialsRevoked = terminalState === 'credentials_revoked' || Boolean(overview?.bridge?.credentialsRevoked);
      const relayHostConflict = Boolean(overview?.bridge?.hostConflict) || isTerminalConflict;

      const startProvisionRequest = async (payload) => {
        setBusy('provision');
        setLastProvisionPayload(payload);
        try {
          const resp = await fetch('/api/tiana-remote/admin/provision', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(payload),
          });
          const data = await resp.json().catch(() => ({}));
          if (!resp.ok) {
            setProvisionStatus({
              running: false,
              step: 'error',
              logs: [],
              error: data.error || `HTTP ${resp.status}`,
              errorCode: data.code || null,
              errorDetails: data.details || null,
            });
            return;
          }
          setProvisionStatus({
            running: true,
            step: data.step || 'starting',
            logs: [],
            error: null,
            errorCode: null,
            errorDetails: null,
          });
          await pollProvisionStatus();
        } finally {
          setBusy('');
        }
      };

      const openForceTakeoverConfirm = (payload, activeHost = null) => {
        setPendingForceTakeover({
          payload: { ...payload, rebind: true, forceRebind: true },
          activeHost,
        });
        forceTakeoverDialogRef.current?.showModal?.();
      };

      const handleConfirmForceTakeover = async () => {
        const req = pendingForceTakeover?.payload;
        setPendingForceTakeover(null);
        if (!req) return;
        await startProvisionRequest(req);
      };

      const handleReconnectBridge = async () => {
        setBusy('reconnect');
        try {
          const resp = await fetch('/api/tiana-remote/admin/reconnect', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: '{}',
          });
          const data = await resp.json().catch(() => ({}));
          if (!resp.ok) {
            setToast(data.error || `Reconnect failed (HTTP ${resp.status})`);
          }
          await fetchState();
        } finally {
          setBusy('');
        }
      };

      const handleToggle = async (nextEnabled) => {
        setBusy('toggle');
        try {
          await fetch('/api/tiana-remote/admin/toggle', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ enabled: nextEnabled }),
          });
          await fetchState();
        } finally {
          setBusy('');
        }
      };

      const handleRevealOrHide = async () => {
        if (revealedKey) {
          setRevealedKey('');
          return;
        }
        setBusy('reveal');
        try {
          const resp = await fetch('/api/tiana-remote/admin/pairing-key/reveal', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: '{}',
          });
          if (resp.ok) {
            const data = await resp.json();
            setRevealedKey(data.pairingKey || '');
          }
        } finally {
          setBusy('');
        }
      };

      const handleCopyKey = async () => {
        let keyToCopy = revealedKey;
        if (!keyToCopy) {
          const resp = await fetch('/api/tiana-remote/admin/pairing-key/reveal', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: '{}',
          });
          if (resp.ok) keyToCopy = (await resp.json()).pairingKey || '';
        }
        if (keyToCopy) await copyText('key', keyToCopy);
      };

      const handleConfirmRotate = async () => {
        setBusy('rotate');
        try {
          const resp = await fetch('/api/tiana-remote/admin/pairing-key/rotate', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ confirm: true }),
          });
          if (resp.ok) {
            const data = await resp.json();
            setRevealedKey(data.pairingKey || '');
            setToast('E2EE pairing key rotated; all remote sessions disconnected.');
            await fetchState();
          }
        } finally {
          setBusy('');
        }
      };

      const handleRenewToken = async () => {
        setBusy('renew');
        try {
          const resp = await fetch('/api/tiana-remote/admin/token/renew', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: '{}',
          });
          const data = await resp.json().catch(() => ({}));
          if (resp.ok) {
            setToast(t('tokenRenewed'));
            await fetchState();
          } else {
            setToast(data.error || `Token renew failed (HTTP ${resp.status})`);
          }
        } finally {
          setBusy('');
        }
      };

      const handleSaveSettings = async (ev) => {
        ev.preventDefault();
        setBusy('settings');
        try {
          const stunUrls = stunDraft.split(',').map((s) => s.trim()).filter(Boolean);
          const resp = await fetch('/api/tiana-remote/admin/settings', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              hostName: hostNameDraft.trim(),
              p2pEnabled: p2pDraft,
              stunUrls: stunUrls.length ? stunUrls : 'none',
            }),
          });
          if (resp.ok) {
            settingsDirtyRef.current = false;
            setSettingsDirty(false);
            setToast(t('saved'));
            await fetchState();
          }
        } finally {
          setBusy('');
        }
      };

      const handleDiscardDrafts = () => {
        settingsDirtyRef.current = false;
        setSettingsDirty(false);
        hydrateDraftsFromOverview(overview);
      };

      const handleRepair = async () => {
        setBusy('repair');
        try {
          const resp = await fetch('/api/tiana-remote/admin/repair', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: '{}',
          });
          if (resp.ok) setToast(t('repaired'));
        } finally {
          setBusy('');
        }
      };

      const handleConfirmUnbind = async () => {
        setBusy('unbind');
        try {
          const resp = await fetch('/api/tiana-remote/admin/unbind', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ confirm: true }),
          });
          const data = await resp.json().catch(() => ({}));
          if (resp.ok) {
            setRevealedKey('');
            setProvisionStatus(null);
            setLastProvisionPayload(null);
            settingsDirtyRef.current = false;
            setSettingsDirty(false);
            bindHostNameDirtyRef.current = false;
            if (overview?.host?.hostName) {
              setBindHostName(overview.host.hostName);
            }
            setBindWebId('');
            setBindForceRebind(false);
            setToast(data.cloudPolicyWarning ? t('unbindDoneCloudWarn') : t('unbindDone'));
            await fetchState();
          } else {
            setToast(data.error || `Unbind failed (HTTP ${resp.status})`);
          }
        } finally {
          setBusy('');
        }
      };

      const handleDisconnectSession = async (sessionId) => {
        await fetch('/api/tiana-remote/admin/sessions/disconnect', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(sessionId ? { sessionId } : { all: true }),
        });
        await fetchState();
      };

      const renderProvisionProgress = () => {
        if (!provisionStatus) return null;
        const isActiveHostConflict = provisionStatus.step === 'error' && provisionStatus.errorCode === 'ACTIVE_HOST_ONLINE';
        const activeHostInfo = provisionStatus.errorDetails || null;
        const takeoverTarget = lastProvisionPayload || (
          activeHostInfo?.webId
            ? { mode: 'bind', webId: activeHostInfo.webId, hostName: hostNameDraft.trim() || bindHostName.trim() || undefined }
            : null
        );
        return h('div', { id: 'dshr-provision-progress', style: { display: 'grid', gap: 8 } },
          h('div', { className: 'dshr-row' },
            h('span', { className: 'dshr-badge' },
              provisionStatus.running ? t('provisionRunning') : (provisionStatus.step === 'done' ? t('provisionDone') : `Status: ${provisionStatus.step}`),
            ),
          ),
          provisionStatus.error && h('div', { className: 'dshr-err' }, provisionStatus.error),
          isActiveHostConflict && takeoverTarget && h('div', { className: 'dshr-row' },
            h('button', {
              type: 'button',
              id: 'dshr-provision-force-takeover-btn',
              className: 'dshr-btn dshr-btn-danger',
              disabled: busy === 'provision',
              onClick: () => openForceTakeoverConfirm(takeoverTarget, activeHostInfo),
            }, t('forceTakeoverBtn')),
          ),
          Array.isArray(provisionStatus.logs) && provisionStatus.logs.length > 0 &&
            h('pre', { className: 'dshr-logs' }, provisionStatus.logs.join('\n')),
        );
      };

      const handleRetryAdminLoad = async () => {
        setBusy('retry');
        try {
          await fetchState();
        } finally {
          setBusy('');
        }
      };

      const isAdminLoadError = Boolean(adminLoadError) && (
        !overview ||
        !overview.configured ||
        adminLoadError.status === 401 ||
        adminLoadError.status === 403
      );
      const isAdminLoadingInitial = !overview && !adminLoadError && adminLoading;
      const isAccessDenied = Boolean(adminLoadError && (adminLoadError.status === 401 || adminLoadError.status === 403));
      const showConfiguredPanel = !isAdminLoadError && configured;
      const showUnconfiguredPanel = !isAdminLoadError && Boolean(overview) && !configured;

      const statusLabel = isAdminLoadError
        ? (isAccessDenied ? t('statusAccessDenied') : t('statusError'))
        : isAdminLoadingInitial
          ? t('statusLoading')
          : !configured
            ? t('statusUnconfigured')
            : !enabled
              ? t('statusPaused')
              : isCredentialsRevoked
                ? t('statusCredentialsRevoked')
                : isTerminalConflict
                  ? t('statusConflictStopped')
                  : relayConnected
                    ? t('statusOnline')
                    : t('statusReconnecting');

      const statusDotClass = isAdminLoadError || isCredentialsRevoked || isTerminalConflict
        ? 'is-error'
        : isAdminLoadingInitial
          ? 'is-warn'
          : (enabled && relayConnected ? 'is-online' : enabled ? 'is-warn' : '');

      const currentAppTakeoverPayload = overview?.web?.id
        ? {
            mode: 'bind',
            webId: overview.web.id,
            hostName: overview?.host?.hostName || undefined,
          }
        : null;

      return h('div', { className: 'dshr-root', 'data-dshr-mode': 'local' },
        h('div', { className: 'dshr-wrap' },
          h('div', { className: 'dshr-header' },
            h('div', null,
              h('h2', { className: 'dshr-title' }, t('title')),
              h('p', { className: 'dshr-sub' }, t('subtitleLocal')),
            ),
            h('div', { className: 'dshr-row' },
              h('span', { className: 'dshr-badge', id: 'dshr-local-status-badge' },
                h('span', { className: `dshr-dot ${statusDotClass}` }),
                statusLabel,
              ),
              showConfiguredPanel && h('label', { className: 'dshr-switch' },
                h('input', {
                  type: 'checkbox',
                  id: 'dshr-enable-toggle',
                  checked: enabled,
                  disabled: busy === 'toggle',
                  onChange: (e) => void handleToggle(e.target.checked),
                }),
                t('toggleLabel'),
              ),
            ),
          ),

          toast && h('div', { className: 'dshr-notice', role: 'status' }, toast),

          showConfiguredPanel && (bridgeConflict || relayHostConflict) && h('div', {
            className: 'dshr-card',
            id: 'dshr-bridge-conflict-banner',
            role: 'alert',
          },
            h('div', { className: 'dshr-card-head' },
              h('h3', { className: 'dshr-card-title' }, t('conflictBannerTitle')),
              bridgeConflict?.ownerPid && h('span', { className: 'dshr-badge' }, `PID ${bridgeConflict.ownerPid}`),
              !bridgeConflict && isTerminalConflict && h('span', { className: 'dshr-badge' },
                overview?.bridge?.lastCloseCode === 4009 ? 'WS 4009' : 'HTTP 409',
              ),
            ),
            h('div', { className: isTerminalConflict ? 'dshr-err' : 'dshr-warn' },
              bridgeConflict
                ? `${t('conflictBannerOwnedByOther')}${bridgeConflict.ownerOrigin ? ` (${bridgeConflict.ownerOrigin})` : ''}`
                : isTerminalConflict
                  ? t('conflictBannerTerminal')
                  : t('conflictBannerRelayKicked'),
            ),
            h('div', { className: 'dshr-row' },
              h('button', {
                type: 'button',
                id: 'dshr-retry-connect-btn',
                className: 'dshr-btn dshr-btn-primary',
                disabled: busy === 'reconnect',
                onClick: () => void handleReconnectBridge(),
              }, busy === 'reconnect' ? t('retryingConnect') : t('retryConnectBtn')),
              isTerminalConflict && currentAppTakeoverPayload && h('button', {
                type: 'button',
                id: 'dshr-force-takeover-btn',
                className: 'dshr-btn dshr-btn-danger',
                disabled: busy === 'provision' || Boolean(provisionStatus?.running),
                onClick: () => openForceTakeoverConfirm(currentAppTakeoverPayload, {
                  hostId: overview?.host?.hostId || '',
                  hostName: overview?.host?.hostName || '',
                }),
              }, t('forceTakeoverBtn')),
            ),
          ),

          showConfiguredPanel && isCredentialsRevoked && h('div', {
            className: 'dshr-card',
            id: 'dshr-credentials-revoked-banner',
            role: 'alert',
          },
            h('div', { className: 'dshr-card-head' },
              h('h3', { className: 'dshr-card-title' }, t('revokedBannerTitle')),
              h('span', { className: 'dshr-badge' }, 'HTTP 403'),
            ),
            h('div', { className: 'dshr-err' }, t('revokedBannerBody')),
            h('div', { className: 'dshr-row' },
              currentAppTakeoverPayload && h('button', {
                type: 'button',
                id: 'dshr-revoked-force-takeover-btn',
                className: 'dshr-btn dshr-btn-danger',
                disabled: busy === 'provision' || Boolean(provisionStatus?.running),
                onClick: () => openForceTakeoverConfirm(currentAppTakeoverPayload, {
                  hostId: overview?.host?.hostId || '',
                  hostName: overview?.host?.hostName || '',
                }),
              }, t('forceTakeoverBtn')),
              h('button', {
                type: 'button',
                id: 'dshr-revoked-retry-connect-btn',
                className: 'dshr-btn',
                disabled: busy === 'reconnect',
                onClick: () => void handleReconnectBridge(),
              }, busy === 'reconnect' ? t('retryingConnect') : t('retryConnectBtn')),
            ),
          ),

          // Explicit admin load error card (prevents falsely rendering "Not bound yet" on 403/5xx/network failure)
          isAdminLoadError && h('div', { className: 'dshr-card', id: 'dshr-admin-error-card', role: 'alert' },
            h('div', { className: 'dshr-card-head' },
              h('h3', { className: 'dshr-card-title' }, isAccessDenied ? t('adminAccessDeniedTitle') : t('adminErrorTitle')),
              h('span', { className: 'dshr-badge', id: 'dshr-admin-error-status' },
                adminLoadError.status ? `HTTP ${adminLoadError.status}` : 'NETWORK',
              ),
            ),
            h('div', { className: 'dshr-err', id: 'dshr-admin-error-message' }, adminLoadError.message),
            h('div', { className: 'dshr-label' }, t('adminErrorHint')),
            h('div', { className: 'dshr-row' },
              h('button', {
                type: 'button',
                id: 'dshr-admin-retry-btn',
                className: 'dshr-btn dshr-btn-primary',
                disabled: busy === 'retry',
                onClick: () => void handleRetryAdminLoad(),
              }, t('retry')),
            ),
          ),

          // Initial loading card before first admin overview response
          isAdminLoadingInitial && h('div', { className: 'dshr-card', id: 'dshr-admin-loading-card' },
            h('div', { className: 'dshr-label' }, t('loadingOverview')),
          ),

          // Unconfigured interactive onboarding card (Bind existing OR Create new Tiana app)
          showUnconfiguredPanel && h('div', { className: 'dshr-card', id: 'dshr-unconfigured-card' },
            h('div', { className: 'dshr-card-head' },
              h('h3', { className: 'dshr-card-title' }, t('onboardTitle')),
            ),
            h('div', { className: 'dshr-tabs', role: 'tablist' },
              h('button', {
                type: 'button',
                role: 'tab',
                className: 'dshr-tab',
                id: 'dshr-tab-bind',
                'aria-selected': onboardTab === 'bind' ? 'true' : 'false',
                onClick: () => setOnboardTab('bind'),
              }, t('onboardBindTab')),
              h('button', {
                type: 'button',
                role: 'tab',
                className: 'dshr-tab',
                id: 'dshr-tab-create',
                'aria-selected': onboardTab === 'create' ? 'true' : 'false',
                onClick: () => setOnboardTab('create'),
              }, t('onboardCreateTab')),
            ),
            onboardTab === 'bind'
              ? h('form', {
                  id: 'dshr-bind-form',
                  style: { display: 'grid', gap: 12 },
                  onSubmit: (e) => {
                    e.preventDefault();
                    if (!bindWebId.trim()) return;
                    void startProvisionRequest({
                      mode: 'bind',
                      webId: bindWebId.trim(),
                      hostName: bindHostName.trim() || undefined,
                      rebind: bindForceRebind,
                    });
                  },
                },
                  overview?.lastBound?.webId && h('div', { className: 'dshr-action-item', id: 'dshr-last-bound-bar' },
                    h('div', { className: 'dshr-action-copy' },
                      h('div', { className: 'dshr-action-title' },
                        `${t('lastBoundLabel')}${isZh ? '：' : ': '}${overview.lastBound.webName || overview.lastBound.webId} (${overview.lastBound.webId})`,
                      ),
                      overview.lastBound.endpoint && h('div', { className: 'dshr-action-desc' }, overview.lastBound.endpoint),
                    ),
                    h('div', { className: 'dshr-action-control' },
                      h('button', {
                        type: 'button',
                        id: 'dshr-last-bound-rebind-btn',
                        className: 'dshr-btn dshr-btn-primary',
                        disabled: busy === 'provision' || Boolean(provisionStatus?.running),
                        onClick: () => {
                          const lastId = overview.lastBound.webId;
                          setBindWebId(lastId);
                          void startProvisionRequest({
                            mode: 'bind',
                            webId: lastId,
                            hostName: bindHostName.trim() || overview?.host?.hostName || undefined,
                            rebind: bindForceRebind,
                          });
                        },
                      }, t('rebindLastBoundBtn')),
                    ),
                  ),
                  h('label', { className: 'dshr-field' },
                    h('span', { className: 'dshr-label' }, t('webIdLabel')),
                    h('input', {
                      id: 'dshr-bind-web-id',
                      className: 'dshr-input',
                      value: bindWebId,
                      placeholder: 'abc123456789',
                      onChange: (e) => setBindWebId(e.target.value),
                    }),
                  ),
                  h('label', { className: 'dshr-field' },
                    h('span', { className: 'dshr-label' }, t('hostName')),
                    h('input', {
                      id: 'dshr-bind-hostname',
                      className: 'dshr-input',
                      value: bindHostName,
                      placeholder: 'My-Workstation',
                      onChange: (e) => {
                        bindHostNameDirtyRef.current = true;
                        setBindHostName(e.target.value);
                      },
                    }),
                  ),
                  h('label', { className: 'dshr-switch' },
                    h('input', {
                      type: 'checkbox',
                      checked: bindForceRebind,
                      onChange: (e) => setBindForceRebind(e.target.checked),
                    }),
                    t('rebindForceLabel'),
                  ),
                  h('div', { className: 'dshr-row' },
                    h('button', {
                      type: 'submit',
                      id: 'dshr-bind-submit',
                      className: 'dshr-btn dshr-btn-primary',
                      disabled: busy === 'provision' || Boolean(provisionStatus?.running) || !bindWebId.trim(),
                    }, t('bindSubmitBtn')),
                  ),
                )
              : h('form', {
                  id: 'dshr-create-form',
                  style: { display: 'grid', gap: 12 },
                  onSubmit: (e) => {
                    e.preventDefault();
                    void startProvisionRequest({
                      mode: 'create',
                      webName: createWebName.trim() || 'dsh-tiana-remote',
                      hostName: bindHostName.trim() || undefined,
                    });
                  },
                },
                  h('label', { className: 'dshr-field' },
                    h('span', { className: 'dshr-label' }, t('webNameLabel')),
                    h('input', {
                      id: 'dshr-create-web-name',
                      className: 'dshr-input',
                      value: createWebName,
                      onChange: (e) => setCreateWebName(e.target.value),
                    }),
                  ),
                  h('label', { className: 'dshr-field' },
                    h('span', { className: 'dshr-label' }, t('hostName')),
                    h('input', {
                      id: 'dshr-create-hostname',
                      className: 'dshr-input',
                      value: bindHostName,
                      placeholder: 'My-Workstation',
                      onChange: (e) => {
                        bindHostNameDirtyRef.current = true;
                        setBindHostName(e.target.value);
                      },
                    }),
                  ),
                  h('div', { className: 'dshr-row' },
                    h('button', {
                      type: 'submit',
                      id: 'dshr-create-submit',
                      className: 'dshr-btn dshr-btn-primary',
                      disabled: busy === 'provision' || Boolean(provisionStatus?.running),
                    }, t('createSubmitBtn')),
                  ),
                ),
            renderProvisionProgress(),
          ),

          // Card 1: Remote URL & QR
          showConfiguredPanel && h('div', { className: 'dshr-card' },
            h('div', { className: 'dshr-card-head' },
              h('h3', { className: 'dshr-card-title' }, t('remoteUrl')),
              h('span', { className: 'dshr-label' }, overview?.host?.hostName || overview?.host?.hostId),
            ),
            h('div', { className: 'dshr-row' },
              h('div', { className: 'dshr-mono', title: endpoint }, endpoint),
              h('button', { type: 'button', className: 'dshr-btn', onClick: () => void copyText('url', endpoint) },
                copiedTag === 'url' ? t('copied') : t('copy')),
              h('a', { className: 'dshr-btn dshr-btn-primary', href: endpoint, target: '_blank', rel: 'noopener noreferrer', style: { textDecoration: 'none' } }, t('open')),
              h('button', {
                type: 'button', className: 'dshr-btn', id: 'dshr-qr-btn',
                onClick: () => qrDialogRef.current?.showModal?.(),
              }, t('qrCode')),
            ),
          ),

          // Card 2: E2EE Pairing Key
          showConfiguredPanel && h('div', { className: 'dshr-card' },
            h('div', { className: 'dshr-card-head' },
              h('h3', { className: 'dshr-card-title' }, t('e2eeTitle')),
              h('span', { className: 'dshr-badge' }, `${t('e2eeFingerprint')}: ${overview?.e2ee?.fingerprint || '—'}`),
            ),
            h('div', { className: 'dshr-row' },
              h('div', { className: 'dshr-mono', id: 'dshr-pairing-key-display' },
                revealedKey || 'dshk1_•••••••••••••••••••••••••••••••••••••••••••'),
              h('button', {
                type: 'button', className: 'dshr-btn', id: 'dshr-reveal-key-btn',
                disabled: busy === 'reveal',
                onClick: () => void handleRevealOrHide(),
              }, revealedKey ? t('hideKey') : t('revealKey')),
              h('button', {
                type: 'button', className: 'dshr-btn', id: 'dshr-copy-key-btn',
                onClick: () => void handleCopyKey(),
              }, copiedTag === 'key' ? t('copied') : t('copyKey')),
              h('button', {
                type: 'button', className: 'dshr-btn dshr-btn-danger', id: 'dshr-rotate-key-btn',
                disabled: busy === 'rotate',
                onClick: () => rotateDialogRef.current?.showModal?.(),
              }, t('rotateKey')),
            ),
          ),

          // Card 3: Active Sessions & Function Token Expiry / Renew
          showConfiguredPanel && h('div', { className: 'dshr-card' },
            h('div', { className: 'dshr-card-head' },
              h('h3', { className: 'dshr-card-title' }, `${t('sessionsTitle')} (${sessions.length})`),
              sessions.length > 0 && h('button', {
                type: 'button', className: 'dshr-btn dshr-btn-danger',
                onClick: () => void handleDisconnectSession(null),
              }, t('disconnectAll')),
            ),
            sessions.length === 0
              ? h('div', { className: 'dshr-label' }, t('sessionsEmpty'))
              : sessions.map((s) => h('div', { key: s.id, className: 'dshr-session-item' },
                  h('div', { className: 'dshr-row' },
                    h('strong', { style: { fontSize: 13 } }, s.sessionId),
                    h('span', { className: 'dshr-badge' }, String(s.transport || 'relay').toUpperCase()),
                    h('span', { className: 'dshr-label' }, `RTT: ${s.rttMs != null ? `${s.rttMs} ms` : '—'}`),
                    h('span', { className: 'dshr-label' }, formatDuration(s.connectedDurationMs)),
                  ),
                  h('button', {
                    type: 'button', className: 'dshr-btn dshr-btn-danger',
                    onClick: () => void handleDisconnectSession(s.id),
                  }, t('disconnect')),
                )),
            h('div', { className: 'dshr-divider' }),
            h('div', { className: 'dshr-card-head' },
              h('div', { className: 'dshr-row' },
                h('span', { className: 'dshr-label' }, `${t('tokenExpiry')}:`),
                h('span', { className: 'dshr-badge', id: 'dshr-token-expiry' }, formatTokenExpiry(tokenExpiresAt, isZh)),
              ),
              h('button', {
                type: 'button',
                className: 'dshr-btn',
                id: 'dshr-renew-token-btn',
                disabled: busy === 'renew',
                onClick: () => void handleRenewToken(),
              }, busy === 'renew' ? t('tokenRenewing') : t('renewToken')),
            ),
          ),

          // Card 4: Host, Network & Switch/Rebind Cloud App
          showConfiguredPanel && h('div', { className: 'dshr-card' },
            h('form', { style: { display: 'grid', gap: 14 }, onSubmit: handleSaveSettings },
              h('div', { className: 'dshr-card-head' },
                h('h3', { className: 'dshr-card-title' }, t('settingsTitle')),
              ),
              h('label', { className: 'dshr-field' },
                h('span', { className: 'dshr-label' }, t('hostName')),
                h('input', {
                  id: 'dshr-hostname-input',
                  className: 'dshr-input', value: hostNameDraft, maxLength: 128,
                  onChange: (e) => { markDirty(); setHostNameDraft(e.target.value); },
                }),
              ),
              h('label', { className: 'dshr-switch' },
                h('input', {
                  id: 'dshr-p2p-checkbox',
                  type: 'checkbox', checked: p2pDraft,
                  onChange: (e) => { markDirty(); setP2pDraft(e.target.checked); },
                }),
                t('p2pToggle'),
              ),
              h('label', { className: 'dshr-field' },
                h('span', { className: 'dshr-label' }, t('stunUrls')),
                h('input', {
                  id: 'dshr-stun-input',
                  className: 'dshr-input', value: stunDraft,
                  placeholder: 'stun:stun.cloudflare.com:3478',
                  onChange: (e) => { markDirty(); setStunDraft(e.target.value); },
                }),
              ),
              h('div', { className: 'dshr-row' },
                h('button', { type: 'submit', id: 'dshr-save-settings-btn', className: 'dshr-btn dshr-btn-primary', disabled: busy === 'settings' },
                  busy === 'settings' ? t('saving') : t('saveSettings')),
                settingsDirty && h('button', { type: 'button', className: 'dshr-btn', onClick: handleDiscardDrafts },
                  t('resetDraft')),
              ),
            ),

            h('div', { className: 'dshr-divider' }),

            // Sync / repair hosted cloud page structured action row
            h('div', { className: 'dshr-action-list', id: 'dshr-local-actions' },
              h('div', { className: 'dshr-action-item', id: 'dshr-local-action-repair' },
                h('div', { className: 'dshr-action-copy' },
                  h('div', { className: 'dshr-action-title' }, t('repairTitle')),
                  h('div', { className: 'dshr-action-desc', id: 'dshr-repair-desc' }, t('repairDesc')),
                ),
                h('div', { className: 'dshr-action-control' },
                  h('button', {
                    type: 'button',
                    className: 'dshr-btn',
                    id: 'dshr-repair-btn',
                    'aria-describedby': 'dshr-repair-desc',
                    disabled: busy === 'repair',
                    onClick: () => void handleRepair(),
                  }, busy === 'repair' ? t('repairing') : t('repairBtn')),
                ),
              ),
            ),

            h('div', { className: 'dshr-divider' }),

            // Cloud app binding summary + unbind action (replaces inline rebind form)
            h('div', { className: 'dshr-action-list', id: 'dshr-cloud-binding-section' },
              h('div', { className: 'dshr-action-item', id: 'dshr-local-action-unbind' },
                h('div', { className: 'dshr-action-copy' },
                  h('div', { className: 'dshr-action-title' }, t('cloudBindingTitle')),
                  h('div', { className: 'dshr-row', id: 'dshr-cloud-binding-meta' },
                    h('span', { className: 'dshr-badge' },
                      `${overview?.web?.name || 'dsh-tiana-remote'} (${overview?.web?.id || '—'})`,
                    ),
                    (overview?.owner?.email || overview?.owner?.displayName || overview?.owner?.spaceName) && h('span', { className: 'dshr-badge' },
                      [overview?.owner?.email || overview?.owner?.displayName, overview?.owner?.spaceName].filter(Boolean).join(' · '),
                    ),
                  ),
                  h('div', { className: 'dshr-action-desc', id: 'dshr-unbind-desc' }, t('unbindDesc')),
                ),
                h('div', { className: 'dshr-action-control' },
                  h('button', {
                    type: 'button',
                    id: 'dshr-unbind-btn',
                    className: 'dshr-btn dshr-btn-danger',
                    'aria-describedby': 'dshr-unbind-desc',
                    disabled: busy === 'unbind' || Boolean(provisionStatus?.running),
                    onClick: () => unbindDialogRef.current?.showModal?.(),
                  }, busy === 'unbind' ? t('unbinding') : t('unbindBtn')),
                ),
              ),
              renderProvisionProgress(),
            ),
          ),

          // Native modal <dialog> for destructive key rotation (autofocus on safe Cancel action)
          h('dialog', {
            ref: rotateDialogRef,
            className: 'dshr-dialog',
            'aria-labelledby': 'dshr-rotate-title',
            onClose: (e) => {
              const dialog = e.currentTarget;
              const val = dialog.returnValue;
              dialog.returnValue = '';
              if (val === 'confirm') void handleConfirmRotate();
            },
          },
            h('h3', { id: 'dshr-rotate-title', style: { margin: '0 0 8px', fontSize: 16 } }, t('rotateConfirmTitle')),
            h('p', { style: { margin: '0 0 16px', fontSize: 13, lineHeight: 1.5, opacity: 0.85 } }, t('rotateConfirmBody')),
            h('form', { method: 'dialog', className: 'dshr-row', style: { justifyContent: 'flex-end' } },
              h('button', { type: 'submit', value: 'cancel', autoFocus: true, className: 'dshr-btn' }, t('cancel')),
              h('button', { type: 'submit', value: 'confirm', className: 'dshr-btn dshr-btn-danger' }, t('rotateConfirmBtn')),
            ),
          ),

          // Native modal <dialog> for Real Scannable QR Code
          h('dialog', {
            ref: qrDialogRef,
            className: 'dshr-dialog',
            id: 'dshr-qr-dialog',
            'aria-labelledby': 'dshr-qr-title',
            onClose: (e) => { e.currentTarget.returnValue = ''; },
          },
            h('h3', { id: 'dshr-qr-title', style: { margin: '0 0 10px', fontSize: 16 } }, t('qrTitle')),
            endpoint && buildQrSvgData(endpoint),
            h('p', { style: { margin: '12px 0 14px', fontSize: 12, lineHeight: 1.5, opacity: 0.85 } }, t('qrHint')),
            h('form', { method: 'dialog', className: 'dshr-row', style: { justifyContent: 'flex-end' } },
              h('button', { type: 'submit', value: 'close', autoFocus: true, className: 'dshr-btn' }, t('close')),
            ),
          ),

          // Native modal <dialog> for explicit secondary confirmation of Force Takeover (autofocus on safe Cancel)
          h('dialog', {
            ref: forceTakeoverDialogRef,
            className: 'dshr-dialog',
            id: 'dshr-force-takeover-dialog',
            'aria-labelledby': 'dshr-force-takeover-title',
            onClose: (e) => {
              const dialog = e.currentTarget;
              const val = dialog.returnValue;
              dialog.returnValue = '';
              if (val === 'confirm') void handleConfirmForceTakeover();
              else setPendingForceTakeover(null);
            },
          },
            h('h3', { id: 'dshr-force-takeover-title', style: { margin: '0 0 8px', fontSize: 16 } }, t('forceTakeoverConfirmTitle')),
            pendingForceTakeover?.activeHost && (pendingForceTakeover.activeHost.hostName || pendingForceTakeover.activeHost.hostId) && h('p', {
              style: { margin: '0 0 8px', fontSize: 13, fontWeight: 600 },
            }, `${t('activeHostLabel')}: ${pendingForceTakeover.activeHost.hostName || pendingForceTakeover.activeHost.hostId}${pendingForceTakeover.activeHost.hostId ? ` (${pendingForceTakeover.activeHost.hostId})` : ''}`),
            h('p', { style: { margin: '0 0 16px', fontSize: 13, lineHeight: 1.5, opacity: 0.85 } }, t('forceTakeoverConfirmBody')),
            h('form', { method: 'dialog', className: 'dshr-row', style: { justifyContent: 'flex-end' } },
              h('button', { type: 'submit', value: 'cancel', autoFocus: true, className: 'dshr-btn', id: 'dshr-force-takeover-cancel' }, t('cancel')),
              h('button', { type: 'submit', value: 'confirm', className: 'dshr-btn dshr-btn-danger', id: 'dshr-force-takeover-confirm' }, t('forceTakeoverConfirmBtn')),
            ),
          ),
          // Native modal <dialog> for explicit secondary confirmation of Unbind Cloud App (autofocus on safe Cancel)
          h('dialog', {
            ref: unbindDialogRef,
            className: 'dshr-dialog',
            id: 'dshr-unbind-dialog',
            'aria-labelledby': 'dshr-unbind-title',
            onClose: (e) => {
              const dialog = e.currentTarget;
              const val = dialog.returnValue;
              dialog.returnValue = '';
              if (val === 'confirm') void handleConfirmUnbind();
            },
          },
            h('h3', { id: 'dshr-unbind-title', style: { margin: '0 0 8px', fontSize: 16 } }, t('unbindConfirmTitle')),
            overview?.web?.id && h('p', {
              style: { margin: '0 0 8px', fontSize: 13, fontWeight: 600 },
            }, `${overview.web.name || 'dsh-tiana-remote'} (${overview.web.id})${overview?.owner?.email || overview?.owner?.spaceName ? ` · ${[overview.owner.email, overview.owner.spaceName].filter(Boolean).join(' / ')}` : ''}`),
            h('p', { style: { margin: '0 0 16px', fontSize: 13, lineHeight: 1.5, opacity: 0.85 } }, t('unbindConfirmBody')),
            h('form', { method: 'dialog', className: 'dshr-row', style: { justifyContent: 'flex-end' } },
              h('button', { type: 'submit', value: 'cancel', autoFocus: true, className: 'dshr-btn', id: 'dshr-unbind-cancel' }, t('cancel')),
              h('button', { type: 'submit', value: 'confirm', className: 'dshr-btn dshr-btn-danger', id: 'dshr-unbind-confirm' }, t('unbindConfirmBtn')),
            ),
          ),
        ),
      );
    }

    return {
      inject: ['slots', 'locale'],
      TianaRemotePanel,
      encodeQrMatrix,
      apply(ctx) {
        if (ctx.locale?.register) {
          ctx.effect(() => ctx.locale.register(NS, { en, zh }), 'tiana-remote:locale');
        }
        const t = ctx.locale?.bind ? ctx.locale.bind(NS) : (k) => zh[k] || k;

        ctx.slots.inject('main', () =>
          ctx.slots.register(
            { name: 'main', key: PANEL_ID, locale: NS },
            (props) => h(TianaRemotePanel, { ...props, t }),
          ),
        );

        ctx.slots.inject('sidebar.panellist', () =>
          ctx.slots.register(
            {
              name: 'sidebar.panellist',
              id: PANEL_ID,
              order: 13,
              priority: 65,
              locale: NS,
              label: () => t('panel'),
            },
            RemoteIcon,
          ),
        );
      },
    };
  }

  if (typeof globalThis !== 'undefined') {
    globalThis.__DSH_REMOTE_QR_ENCODE__ = encodeQrMatrix;
    globalThis.__DSH_REMOTE_CLIENT_FACTORY__ = factory;
    if (globalThis.__ModuleLoader__ && typeof globalThis.__ModuleLoader__.load === 'function') {
      globalThis.__ModuleLoader__.load({
        id: '@tianacloud/dsh-remote',
        factory,
      });
    }
  }
})();
