/**
 * ProofChain Batches & Ledger Status Controller (/batches)
 */

(async function () {
  'use strict';

  await ProofChainStore.initializeLedgerIfEmpty();

  const batchTableBody = document.getElementById('batchTableBody');
  const batches = ProofChainStore.getBatches();

  renderBatchesTable(batches);

  function renderBatchesTable(batchList) {
    batchTableBody.innerHTML = '';

    if (!batchList || batchList.length === 0) {
      batchTableBody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 24px;">No batches recorded in ledger.</td></tr>';
      return;
    }

    batchList.forEach((batch, index) => {
      const tr = document.createElement('tr');
      tr.className = 'clickable-row';
      tr.setAttribute('data-index', index);

      const stateBadgeClass = batch.state === 'ANCHORED' 
        ? 'badge-anchored' 
        : (batch.state === 'SEALED' ? 'badge-sealed' : 'badge-pending');

      const truncatedRoot = batch.root ? (batch.root.substring(0, 8) + '...' + batch.root.substring(56)) : 'PENDING';
      const truncatedPrev = batch.prev_checkpoint_hash ? (batch.prev_checkpoint_hash.substring(0, 8) + '...' + batch.prev_checkpoint_hash.substring(56)) : 'NONE';
      const truncatedSig = batch.signature ? (batch.signature.substring(0, 14) + '...') : 'PENDING';

      tr.innerHTML = `
        <td class="mono-cell">${batch.batch_id}</td>
        <td>${batch.tree_size}</td>
        <td class="mono-cell" title="${batch.root}">${truncatedRoot}</td>
        <td class="mono-cell" title="${batch.prev_checkpoint_hash}">${truncatedPrev}</td>
        <td class="mono-cell">${batch.timestamp}</td>
        <td class="mono-cell" title="${batch.signature}">${truncatedSig}</td>
        <td><span class="badge ${stateBadgeClass}">${batch.state}</span></td>
      `;

      // Drawer row
      const drawerTr = document.createElement('tr');
      drawerTr.className = 'batch-drawer';
      drawerTr.id = 'drawer-' + index;
      drawerTr.style.display = 'none';

      drawerTr.innerHTML = `
        <td colspan="7" style="padding: 0;">
          <div style="padding: 20px 24px; background: var(--color-muted); border-top: 1px solid var(--color-border-light);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
              <p class="section-label" style="margin: 0;">Merkle Tree DAG (0x00 Leaf -> 0x01 Interior -> Root)</p>
              <span class="mono" style="font-size: 0.76rem; color: var(--color-secondary);">Batch: ${batch.batch_id}</span>
            </div>
            <div class="tree-dag" id="treeDag-${index}">Generating DAG layout...</div>
            <div style="margin-top: 16px; display: flex; gap: 12px; align-items: center; flex-wrap: wrap;">
              <label class="form-label" style="margin-bottom: 0;">Export Leaf Index:</label>
              <input type="number" class="form-input mono-input" id="leafInput-${index}" style="width: 90px; padding: 6px 10px;" value="0" min="0" max="${Math.max(0, batch.tree_size - 1)}">
              <button class="btn btn-sm btn-outline" id="exportProofBtn-${index}">Download Proof Bundle</button>
            </div>
          </div>
        </td>
      `;

      tr.addEventListener('click', async () => {
        const isCurrentlyOpen = drawerTr.style.display === 'table-row';
        document.querySelectorAll('.batch-drawer').forEach(d => d.style.display = 'none');
        document.querySelectorAll('.clickable-row').forEach(r => r.classList.remove('active-row'));

        if (!isCurrentlyOpen) {
          drawerTr.style.display = 'table-row';
          tr.classList.add('active-row');
          await loadDagView(batch, index);
        }
      });

      batchTableBody.appendChild(tr);
      batchTableBody.appendChild(drawerTr);

      // Export Proof handler
      const exportBtn = drawerTr.querySelector('#exportProofBtn-' + index);
      exportBtn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const leafInput = drawerTr.querySelector('#leafInput-' + index);
        const selectedIndex = parseInt(leafInput.value, 10) || 0;

        if (!batch.leaves || batch.leaves.length === 0) {
          alert('Batch contains no registered leaves.');
          return;
        }

        const boundedIndex = Math.min(Math.max(0, selectedIndex), batch.leaves.length - 1);
        const tree = await ProofChainCrypto.buildMerkleTree(batch.leaves);
        const proofBundle = await ProofChainCrypto.generateProofBundle(tree, boundedIndex, 'proofchain/v1/file', batch.batch_id);

        const blob = new Blob([JSON.stringify(proofBundle, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `proof-${batch.batch_id}-leaf${boundedIndex}.json`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
      });
    });
  }

  async function loadDagView(batch, index) {
    const container = document.getElementById('treeDag-' + index);
    if (!batch.leaves || batch.leaves.length === 0) {
      container.textContent = 'Empty batch tree. No registered leaves.';
      return;
    }

    const tree = await ProofChainCrypto.buildMerkleTree(batch.leaves);
    let dagText = `Root [0x01]: ${tree.root}\n`;

    if (tree.levels.length > 1) {
      for (let l = tree.levels.length - 2; l >= 0; l--) {
        const levelNodes = tree.levels[l];
        dagText += `\nLevel ${l} (${l === 0 ? 'Leaf Hashes [0x00]' : 'Interior Nodes [0x01]'}):\n`;
        levelNodes.forEach((node, nIdx) => {
          dagText += `  [Node ${nIdx}]: ${node}\n`;
        });
      }
    }

    dagText += '\nRegistered Document Leaves (Fingerprints):\n';
    batch.leaves.forEach((lf, lIdx) => {
      dagText += `  [Leaf ${lIdx}]: ${lf}\n`;
    });

    container.textContent = dagText;
  }

})();
