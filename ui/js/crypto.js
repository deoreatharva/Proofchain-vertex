/**
 * ProofChain Cryptographic and Merkle Verification Engine
 * WebCrypto API (crypto.subtle) - Zero External Dependencies
 */

window.ProofChainCrypto = (function () {
  'use strict';

  async function sha256Bytes(uint8Array) {
    const buffer = await crypto.subtle.digest('SHA-256', uint8Array);
    return new Uint8Array(buffer);
  }

  async function sha256Hex(uint8Array) {
    const bytes = await sha256Bytes(uint8Array);
    return bytesToHex(bytes);
  }

  function bytesToHex(bytes) {
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex;
  }

  function hexToBytes(hexStr) {
    const cleanHex = hexStr.trim().toLowerCase();
    if (cleanHex.length % 2 !== 0) {
      throw new Error('Invalid hex string length');
    }
    const bytes = new Uint8Array(cleanHex.length / 2);
    for (let i = 0; i < cleanHex.length; i += 2) {
      bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
    }
    return bytes;
  }

  function canonicalizeJsonRFC8785(obj) {
    if (obj === null || typeof obj !== 'object') {
      return JSON.stringify(obj);
    }
    if (Array.isArray(obj)) {
      return '[' + obj.map(canonicalizeJsonRFC8785).join(',') + ']';
    }
    const sortedKeys = Object.keys(obj).sort();
    const entries = sortedKeys.map(key => {
      return JSON.stringify(key) + ':' + canonicalizeJsonRFC8785(obj[key]);
    });
    return '{' + entries.join(',') + '}';
  }

  async function computeDocumentFingerprint(format, rawBytes) {
    const tag = new TextEncoder().encode(format);
    let canonicalBytes = rawBytes;

    if (format === 'utf8-nfc') {
      const text = new TextDecoder('utf-8', { fatal: false }).decode(rawBytes);
      const normalized = text.normalize('NFC');
      canonicalBytes = new TextEncoder().encode(normalized);
    } else if (format === 'rfc8785') {
      try {
        const text = new TextDecoder('utf-8').decode(rawBytes);
        const parsed = JSON.parse(text);
        const canonicalString = canonicalizeJsonRFC8785(parsed);
        canonicalBytes = new TextEncoder().encode(canonicalString);
      } catch (e) {
        canonicalBytes = rawBytes;
      }
    }

    const payload = new Uint8Array(tag.length + canonicalBytes.length);
    payload.set(tag, 0);
    payload.set(canonicalBytes, tag.length);

    const hashHex = await sha256Hex(payload);
    return {
      fingerprint: hashHex,
      canonicalBytes: canonicalBytes
    };
  }

  async function computeLeafHash(fingerprintHex) {
    const fpBytes = hexToBytes(fingerprintHex);
    const leafPayload = new Uint8Array(1 + fpBytes.length);
    leafPayload[0] = 0x00;
    leafPayload.set(fpBytes, 1);
    return await sha256Hex(leafPayload);
  }

  async function computeInteriorHash(leftHex, rightHex) {
    const leftBytes = hexToBytes(leftHex);
    const rightBytes = hexToBytes(rightHex);
    const nodePayload = new Uint8Array(1 + leftBytes.length + rightBytes.length);
    nodePayload[0] = 0x01;
    nodePayload.set(leftBytes, 1);
    nodePayload.set(rightBytes, 1 + leftBytes.length);
    return await sha256Hex(nodePayload);
  }

  async function buildMerkleTree(leafFingerprints) {
    if (!leafFingerprints || leafFingerprints.length === 0) {
      return {
        leaves: [],
        levels: [],
        root: '0000000000000000000000000000000000000000000000000000000000000000',
        size: 0
      };
    }

    const leafHashes = [];
    for (let i = 0; i < leafFingerprints.length; i++) {
      const lh = await computeLeafHash(leafFingerprints[i]);
      leafHashes.push(lh);
    }

    // Pad to power of 2 for balanced binary tree audit demo
    let currentLevel = [...leafHashes];
    let nextPowerOfTwo = 1;
    while (nextPowerOfTwo < currentLevel.length) {
      nextPowerOfTwo *= 2;
    }
    while (currentLevel.length < nextPowerOfTwo) {
      currentLevel.push(currentLevel[currentLevel.length - 1]);
    }

    const levels = [currentLevel];
    while (currentLevel.length > 1) {
      const nextLevel = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        const left = currentLevel[i];
        const right = currentLevel[i + 1] || currentLevel[i];
        const parent = await computeInteriorHash(left, right);
        nextLevel.push(parent);
      }
      levels.push(nextLevel);
      currentLevel = nextLevel;
    }

    return {
      leaves: leafFingerprints,
      leafHashes: leafHashes,
      levels: levels,
      root: levels[levels.length - 1][0],
      size: leafFingerprints.length
    };
  }

  async function generateProofBundle(tree, leafIndex, format, batchId) {
    if (leafIndex < 0 || leafIndex >= tree.leaves.length) {
      throw new Error('Leaf index out of bounds');
    }

    const path = [];
    let idx = leafIndex;
    for (let lvl = 0; lvl < tree.levels.length - 1; lvl++) {
      const currentLevel = tree.levels[lvl];
      const siblingIndex = (idx % 2 === 0) ? idx + 1 : idx - 1;
      const siblingHash = (siblingIndex < currentLevel.length) ? currentLevel[siblingIndex] : currentLevel[idx];
      path.push(siblingHash);
      idx = Math.floor(idx / 2);
    }

    return {
      version: 'proofchain-proof/1',
      canonicalization: format || 'proofchain/v1/file',
      fingerprint: tree.leaves[leafIndex],
      leaf_index: leafIndex,
      tree_size: tree.size,
      path: path,
      claimed_root: tree.root,
      batch_id: batchId
    };
  }

  async function evaluateProofPath(fingerprintHex, leafIndex, path) {
    let currentHash = await computeLeafHash(fingerprintHex);
    let idx = leafIndex;

    for (let i = 0; i < path.length; i++) {
      const siblingHex = path[i];
      if (idx % 2 === 0) {
        currentHash = await computeInteriorHash(currentHash, siblingHex);
      } else {
        currentHash = await computeInteriorHash(siblingHex, currentHash);
      }
      idx = Math.floor(idx / 2);
    }
    return currentHash;
  }

  return {
    sha256Hex,
    bytesToHex,
    hexToBytes,
    canonicalizeJsonRFC8785,
    computeDocumentFingerprint,
    computeLeafHash,
    computeInteriorHash,
    buildMerkleTree,
    generateProofBundle,
    evaluateProofPath
  };
})();
