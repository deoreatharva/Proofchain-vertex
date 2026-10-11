/**
 * ProofChain Audit & Tamper Demonstration Engine (/audit)
 * Live Cryptographic Simulation comparing Naive Database vs ProofChain Ledger
 */

(async function () {
  'use strict';

  await ProofChainStore.initializeLedgerIfEmpty();

  const naiveResult = document.getElementById('naiveResult');
  const naiveDetail = document.getElementById('naiveDetail');
  const proofchainResult = document.getElementById('proofchainResult');
  const proofchainDetail = document.getElementById('proofchainDetail');

  const tamperByteBtn = document.getElementById('tamperByteBtn');
  const tamperSiblingBtn = document.getElementById('tamperSiblingBtn');
  const tamperDbBtn = document.getElementById('tamperDbBtn');
  const resetBtn = document.getElementById('resetBtn');

  const mismatchCard = document.getElementById('mismatchCard');
  const divergenceNode = document.getElementById('divergenceNode');
  const treeDagDisplay = document.getElementById('treeDagDisplay');

  // Baseline scenario dataset
  const baseDocumentText = 'ProofChain Sovereign Identity Record: SubjectID=98124, Clearance=LEVEL_4';
  const baselineFormat = 'proofchain/v1/file';
  let activeDocumentBytes = new TextEncoder().encode(baseDocumentText);

  // Pre-seed an audit batch of 4 items to demonstrate full tree traversal
  const sampleBatchFingerprints = [
    (await ProofChainCrypto.computeDocumentFingerprint(baselineFormat, activeDocumentBytes)).fingerprint,
    '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    '8754425983b1a23666d35793fa9bc82d8c3add4d733703cac76150d6a6066a7b',
    '79054025255fb1a26e4bc422aef54eb4d080a14a804f1745204ec37399f5429c'
  ];

  let canonicalTree = await ProofChainCrypto.buildMerkleTree(sampleBatchFingerprints);
  let publishedWitnessRoot = canonicalTree.root;

  // DB record table: doc_id, stored_hash, record_content
  let dbRecord = {
    doc_id: 'DOC-2026-98124',
    content: baseDocumentText,
    stored_hash: sampleBatchFingerprints[0]
  };

  let activeProof = await ProofChainCrypto.generateProofBundle(
    canonicalTree,
    0,
    baselineFormat,
    ProofChainStore.getCurrentYearMonth() + '-B0001'
  );

  async function runReverification(activeMode) {
    document.querySelectorAll('.tamper-btn').forEach(b => b.classList.remove('active'));

    // 1. Column A: Naive DB Check (SHA-256(content) == db.stored_hash)
    const currentDocFpResult = await ProofChainCrypto.computeDocumentFingerprint(baselineFormat, activeDocumentBytes);
    const computedDocFp = currentDocFpResult.fingerprint;

    let naivePassed = false;
    let naiveMessage = '';

    if (computedDocFp === dbRecord.stored_hash) {
      naivePassed = true;
      naiveMessage = 'Document hash matches db.stored_hash directly (' + computedDocFp.substring(0, 12) + '...).';
    } else {
      naivePassed = false;
      naiveMessage = 'DOCUMENT_MODIFIED: Computed SHA-256 (' + computedDocFp.substring(0, 8) + '...) does not match db.stored_hash (' + dbRecord.stored_hash.substring(0, 8) + '...).';
    }

    // 2. Column B: ProofChain External Witness Check
    let proofChainPassed = false;
    let proofChainMessage = '';

    if (computedDocFp !== activeProof.fingerprint) {
      proofChainPassed = false;
      proofChainMessage = 'DOCUMENT_MODIFIED: File hash does not match claimed proof fingerprint.';
    } else {
      let recomputedRoot;
      try {
        recomputedRoot = await ProofChainCrypto.evaluateProofPath(
          activeProof.fingerprint,
          activeProof.leaf_index,
          activeProof.path
        );
      } catch (e) {
        recomputedRoot = 'ERR';
      }

      if (recomputedRoot !== activeProof.claimed_root) {
        proofChainPassed = false;
        proofChainMessage = 'INVALID_PROOF: Merkle proof path recalculation produced ' + recomputedRoot.substring(0, 8) + '... instead of claimed root ' + activeProof.claimed_root.substring(0, 8) + '...';
      } else if (recomputedRoot !== publishedWitnessRoot) {
        proofChainPassed = false;
        proofChainMessage = 'ROOT_MISMATCH: Tree root ' + recomputedRoot.substring(0, 8) + '... does not match external witness checkpoint root ' + publishedWitnessRoot.substring(0, 8) + '...';
      } else {
        proofChainPassed = true;
        proofChainMessage = 'Proof validated against published witness checkpoint root (' + publishedWitnessRoot.substring(0, 12) + '...).';
      }
    }

    // Update UI elements
    naiveResult.textContent = naivePassed ? 'VERDICT: PASS' : 'VERDICT: FAIL';
    naiveDetail.textContent = naiveMessage;

    proofchainResult.textContent = proofChainPassed ? 'VERDICT: PASS' : 'VERDICT: FAIL';
    proofchainDetail.textContent = proofChainMessage;

    // Handle Subtree Mismatch Locator display
    if (activeMode === 'SIBLING' || activeMode === 'DB') {
      mismatchCard.style.display = 'block';
      renderSubtreeMismatchLocator(activeMode);
    } else {
      mismatchCard.style.display = 'none';
    }
  }

  function renderSubtreeMismatchLocator(mode) {
    if (mode === 'SIBLING') {
      divergenceNode.textContent = 'Sibling Path Index 0 (Interior Node 0x01): Corrupted sibling ' + activeProof.path[0].substring(0, 16) + '...';
      treeDagDisplay.textContent = 
`[ROOT: Published Witness Checkpoint] ${publishedWitnessRoot}
       |
       +--- [Interior Node 0]
       |         |
       |         +--- [Leaf 0 (Target Document)] ${sampleBatchFingerprints[0].substring(0, 16)}...
       |         +--- [MISMATCH: Corrupted Sibling 1] ${activeProof.path[0].substring(0, 16)}... [INVALID_PROOF]
       |
       +--- [Interior Node 1] Valid Branch`;
    } else if (mode === 'DB') {
      divergenceNode.textContent = 'Root Checkpoint Anchor (0x01): Local DB Root diverges from Witness Root (' + publishedWitnessRoot.substring(0, 16) + '...)';
      treeDagDisplay.textContent = 
`[PUBLISHED WITNESS ROOT] ${publishedWitnessRoot}
       |  (Divergence Detected: Local Database was silently modified and rebuilt)
       X  [MISMATCH: Recomputed Local DB Root] ${activeProof.claimed_root} [ROOT_MISMATCH]
       |
       +--- [Tampered DB Record Leaf 0] ${dbRecord.stored_hash.substring(0, 16)}...
            (Naive Registry marked this as valid because db.stored_hash matched the altered row)`;
    }
  }

  // --- Reset Simulation ---
  resetBtn.addEventListener('click', async () => {
    activeDocumentBytes = new TextEncoder().encode(baseDocumentText);
    dbRecord.stored_hash = sampleBatchFingerprints[0];
    dbRecord.content = baseDocumentText;

    canonicalTree = await ProofChainCrypto.buildMerkleTree(sampleBatchFingerprints);
    publishedWitnessRoot = canonicalTree.root;

    activeProof = await ProofChainCrypto.generateProofBundle(
      canonicalTree,
      0,
      baselineFormat,
      ProofChainStore.getCurrentYearMonth() + '-B0001'
    );

    await runReverification('NONE');
  });

  // --- Tamper 1: Corrupt 1 byte in file ---
  tamperByteBtn.addEventListener('click', async () => {
    tamperByteBtn.classList.add('active');
    // Mutate 1 byte
    activeDocumentBytes = new Uint8Array(new TextEncoder().encode(baseDocumentText));
    activeDocumentBytes[0] = activeDocumentBytes[0] ^ 0xFF; // flip bits of first byte

    await runReverification('BYTE');
  });

  // --- Tamper 2: Corrupt Proof Sibling Hash ---
  tamperSiblingBtn.addEventListener('click', async () => {
    tamperSiblingBtn.classList.add('active');
    activeDocumentBytes = new TextEncoder().encode(baseDocumentText);

    activeProof = await ProofChainCrypto.generateProofBundle(
      canonicalTree,
      0,
      baselineFormat,
      ProofChainStore.getCurrentYearMonth() + '-B0001'
    );

    // Corrupt sibling in path
    if (activeProof.path.length > 0) {
      activeProof.path[0] = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
    }

    await runReverification('SIBLING');
  });

  // --- Tamper 3: Modify DB Record & Rebuild DB Root ---
  tamperDbBtn.addEventListener('click', async () => {
    tamperDbBtn.classList.add('active');
    const tamperedContent = 'ProofChain Sovereign Identity Record: SubjectID=98124, Clearance=ADMIN_ROOT';
    activeDocumentBytes = new TextEncoder().encode(tamperedContent);

    // Naive DB admin silently updates the stored_hash in the database to match!
    const tamperedFpResult = await ProofChainCrypto.computeDocumentFingerprint(baselineFormat, activeDocumentBytes);
    dbRecord.content = tamperedContent;
    dbRecord.stored_hash = tamperedFpResult.fingerprint;

    // Database recomputes its internal Merkle root based on its altered table
    const alteredLeaves = [...sampleBatchFingerprints];
    alteredLeaves[0] = tamperedFpResult.fingerprint;
    const alteredTree = await ProofChainCrypto.buildMerkleTree(alteredLeaves);

    // Local proof uses altered tree root
    activeProof = await ProofChainCrypto.generateProofBundle(
      alteredTree,
      0,
      baselineFormat,
      ProofChainStore.getCurrentYearMonth() + '-B0001'
    );

    // Published witness root remains original independent external anchor!
    await runReverification('DB');
  });

  // Initial Run
  await runReverification('NONE');

})();
