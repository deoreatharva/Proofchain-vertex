/**
 * ProofChain Shared State & Ledger Store
 * Synchronizes batches, documents, and checkpoints across views via localStorage
 */

window.ProofChainStore = (function () {
  'use strict';

  const STORAGE_KEY_BATCHES = 'proofchain_batches_v1';
  const STORAGE_KEY_DOCS = 'proofchain_registered_docs_v1';

  function getCurrentYearMonth() {
    const now = new Date();
    const year = now.getUTCFullYear();
    const month = String(now.getUTCMonth() + 1).padStart(2, '0');
    return `${year}-${month}`;
  }

  async function initializeLedgerIfEmpty() {
    const existing = localStorage.getItem(STORAGE_KEY_BATCHES);
    if (existing) {
      try {
        const parsed = JSON.parse(existing);
        if (Array.isArray(parsed) && parsed.length > 0) {
          return parsed;
        }
      } catch (e) {
        // reinitialize if corrupted
      }
    }

    const ym = getCurrentYearMonth();
    const now = new Date();

    // Generate real cryptographic fingerprints for sample seeds
    const sampleLeaves1 = [
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      '8754425983b1a23666d35793fa9bc82d8c3add4d733703cac76150d6a6066a7b',
      '79054025255fb1a26e4bc422aef54eb4d080a14a804f1745204ec37399f5429c',
      '612f00a505b822d3d9d300e84b803fbcc3c9a667b36f73111f62d1d0337b5883'
    ];
    const tree1 = await ProofChainCrypto.buildMerkleTree(sampleLeaves1);

    const sampleLeaves2 = [
      '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
      'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d'
    ];
    const tree2 = await ProofChainCrypto.buildMerkleTree(sampleLeaves2);

    const ts1 = new Date(now.getTime() - 86400000 * 2).toISOString();
    const ts2 = new Date(now.getTime() - 86400000).toISOString();
    const ts3 = now.toISOString();

    const initialBatches = [
      {
        batch_id: `${ym}-B0001`,
        tree_size: sampleLeaves1.length,
        root: tree1.root,
        prev_checkpoint_hash: '0000000000000000000000000000000000000000000000000000000000000000',
        timestamp: ts1,
        signature: 'ed25519:3df2a7bc916e45f091c8413b562a0d9e77bf82c40156a8d3e2f1b4c5a6d7e8f9',
        state: 'ANCHORED',
        leaves: sampleLeaves1
      },
      {
        batch_id: `${ym}-B0002`,
        tree_size: sampleLeaves2.length,
        root: tree2.root,
        prev_checkpoint_hash: tree1.root,
        timestamp: ts2,
        signature: 'ed25519:6c8a2b4e9f1d0357b284e9102c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d',
        state: 'SEALED',
        leaves: sampleLeaves2
      },
      {
        batch_id: `${ym}-B0003`,
        tree_size: 1,
        root: sampleLeaves1[0],
        prev_checkpoint_hash: tree2.root,
        timestamp: ts3,
        signature: 'ed25519:pending_finalization_before_anchor_witness_aggregation',
        state: 'PENDING',
        leaves: [sampleLeaves1[0]]
      }
    ];

    localStorage.setItem(STORAGE_KEY_BATCHES, JSON.stringify(initialBatches));
    return initialBatches;
  }

  function getBatches() {
    const raw = localStorage.getItem(STORAGE_KEY_BATCHES);
    if (!raw) return [];
    try {
      return JSON.parse(raw);
    } catch (e) {
      return [];
    }
  }

  function saveBatches(batches) {
    localStorage.setItem(STORAGE_KEY_BATCHES, JSON.stringify(batches));
  }

  async function registerDocument(docData) {
    const batches = getBatches();
    let pendingBatch = batches.find(b => b.state === 'PENDING');
    const ym = getCurrentYearMonth();
    const nowIso = new Date().toISOString();

    if (!pendingBatch) {
      const lastBatch = batches[batches.length - 1];
      const prevRoot = lastBatch ? lastBatch.root : '0000000000000000000000000000000000000000000000000000000000000000';
      const nextNum = String(batches.length + 1).padStart(4, '0');
      pendingBatch = {
        batch_id: `${ym}-B${nextNum}`,
        tree_size: 0,
        root: '',
        prev_checkpoint_hash: prevRoot,
        timestamp: nowIso,
        signature: 'ed25519:pending_finalization_before_anchor',
        state: 'PENDING',
        leaves: []
      };
      batches.push(pendingBatch);
    }

    pendingBatch.leaves.push(docData.fingerprint);
    const updatedTree = await ProofChainCrypto.buildMerkleTree(pendingBatch.leaves);
    pendingBatch.tree_size = pendingBatch.leaves.length;
    pendingBatch.root = updatedTree.root;
    pendingBatch.timestamp = nowIso;

    saveBatches(batches);

    // Save registered doc record
    const docs = getRegisteredDocs();
    docs.unshift({
      fingerprint: docData.fingerprint,
      canonicalization: docData.canonicalization,
      fileName: docData.fileName,
      metadata: docData.metadata,
      batch_id: pendingBatch.batch_id,
      leaf_index: pendingBatch.leaves.length - 1,
      registered_at: nowIso
    });
    localStorage.setItem(STORAGE_KEY_DOCS, JSON.stringify(docs));

    // Return real proof bundle
    const proofBundle = await ProofChainCrypto.generateProofBundle(
      updatedTree,
      pendingBatch.leaves.length - 1,
      docData.canonicalization,
      pendingBatch.batch_id
    );

    return {
      batch: pendingBatch,
      proofBundle: proofBundle
    };
  }

  function getRegisteredDocs() {
    const raw = localStorage.getItem(STORAGE_KEY_DOCS);
    if (!raw) return [];
    try {
      return JSON.parse(raw);
    } catch (e) {
      return [];
    }
  }

  return {
    initializeLedgerIfEmpty,
    getBatches,
    saveBatches,
    registerDocument,
    getRegisteredDocs,
    getCurrentYearMonth
  };
})();
