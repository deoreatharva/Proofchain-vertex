/**
 * ProofChain Registration View Controller (/register)
 */

(async function () {
  'use strict';

  await ProofChainStore.initializeLedgerIfEmpty();

  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('fileInput');
  const fileInfo = document.getElementById('fileInfo');
  const fileNameDisplay = document.getElementById('fileName');
  const fileSizeDisplay = document.getElementById('fileSize');
  const canonFormat = document.getElementById('canonFormat');

  const metaIssuer = document.getElementById('metaIssuer');
  const metaDate = document.getElementById('metaDate');
  const metaDocType = document.getElementById('metaDocType');
  const metaCategory = document.getElementById('metaCategory');
  const confirmMetaBtn = document.getElementById('confirmMetaBtn');
  const confirmStatus = document.getElementById('confirmStatus');

  const fingerprintOutput = document.getElementById('fingerprintOutput');
  const copyFpBtn = document.getElementById('copyFpBtn');
  const registerActionBtn = document.getElementById('registerActionBtn');
  const registrationFeedback = document.getElementById('registrationFeedback');

  let currentRawBytes = null;
  let currentFile = null;
  let metadataConfirmed = false;
  let metadataDetails = {};

  // Drag and drop
  dropzone.addEventListener('click', () => fileInput.click());

  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('drag-over');
  });

  dropzone.addEventListener('dragleave', () => {
    dropzone.classList.remove('drag-over');
  });

  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('drag-over');
    if (e.dataTransfer.files.length > 0) {
      processSelectedFile(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
      processSelectedFile(fileInput.files[0]);
    }
  });

  async function processSelectedFile(file) {
    currentFile = file;
    fileNameDisplay.textContent = file.name;
    fileSizeDisplay.textContent = formatBytes(file.size);
    fileInfo.style.display = 'block';

    const buffer = await file.arrayBuffer();
    currentRawBytes = new Uint8Array(buffer);

    populateExtractedMetadata(file);
    await updateFingerprint();

    confirmMetaBtn.disabled = false;
    registerActionBtn.disabled = false;
  }

  function populateExtractedMetadata(file) {
    const today = new Date().toISOString().split('T')[0];
    const extension = file.name.split('.').pop().toLowerCase();

    metaDate.value = today;

    if (extension === 'json') {
      metaDocType.value = 'STRUCTURED_DATA_PAYLOAD';
      metaCategory.value = 'SYSTEM_RECORD';
      metaIssuer.value = 'API_INGESTION_GATEWAY';
    } else if (extension === 'pdf') {
      metaDocType.value = 'GOVERNMENT_CERTIFICATE';
      metaCategory.value = 'ATTESTATION';
      metaIssuer.value = 'STATE_REGISTRAR';
    } else if (['jpg', 'jpeg', 'png'].includes(extension)) {
      metaDocType.value = 'EVIDENTIARY_DOCUMENT';
      metaCategory.value = 'IMAGE_SCAN';
      metaIssuer.value = 'DOCUMENT_CAPTURE_CLIENT';
    } else {
      metaDocType.value = 'GENERAL_DOCUMENT';
      metaCategory.value = 'UNCLASSIFIED';
      metaIssuer.value = 'AUTHORIZED_SUBMITTER';
    }

    metadataConfirmed = false;
    confirmStatus.textContent = '';
    confirmMetaBtn.textContent = 'Confirm Metadata';
  }

  async function updateFingerprint() {
    if (!currentRawBytes) return;

    const format = canonFormat.value;
    const result = await ProofChainCrypto.computeDocumentFingerprint(format, currentRawBytes);
    fingerprintOutput.value = result.fingerprint;
    copyFpBtn.disabled = false;
  }

  canonFormat.addEventListener('change', updateFingerprint);

  // Metadata Confirmation
  confirmMetaBtn.addEventListener('click', () => {
    const nowIso = new Date().toISOString();
    metadataConfirmed = true;
    metadataDetails = {
      issuer: metaIssuer.value.trim(),
      date: metaDate.value.trim(),
      document_type: metaDocType.value.trim(),
      category: metaCategory.value.trim(),
      confirmed_by: 'CLIENT_OPERATOR',
      confirmed_at: nowIso
    };

    confirmStatus.textContent = 'Confirmed by ' + metadataDetails.confirmed_by + ' at ' + metadataDetails.confirmed_at;
    confirmMetaBtn.textContent = 'Confirmed';
    confirmMetaBtn.disabled = true;
  });

  // Copy fingerprint
  copyFpBtn.addEventListener('click', () => {
    if (!fingerprintOutput.value) return;
    navigator.clipboard.writeText(fingerprintOutput.value).then(() => {
      const original = copyFpBtn.textContent;
      copyFpBtn.textContent = 'Copied';
      setTimeout(() => { copyFpBtn.textContent = original; }, 1200);
    });
  });

  // Register into Ledger
  registerActionBtn.addEventListener('click', async () => {
    if (!fingerprintOutput.value || !currentFile) return;

    registerActionBtn.disabled = true;
    registerActionBtn.textContent = 'Registering...';

    const registration = await ProofChainStore.registerDocument({
      fingerprint: fingerprintOutput.value,
      canonicalization: canonFormat.value,
      fileName: currentFile.name,
      metadata: metadataConfirmed ? metadataDetails : {
        issuer: metaIssuer.value.trim(),
        date: metaDate.value.trim(),
        document_type: metaDocType.value.trim(),
        category: metaCategory.value.trim(),
        confirmed_by: 'AUTO_SUBMIT',
        confirmed_at: new Date().toISOString()
      }
    });

    registrationFeedback.style.display = 'block';
    document.getElementById('assignedBatchId').textContent = registration.batch.batch_id;
    document.getElementById('assignedLeafIndex').textContent = registration.proofBundle.leaf_index;
    document.getElementById('activeRootHex').textContent = registration.batch.root;

    // Attach download handler for proof bundle
    const downloadBtn = document.getElementById('downloadProofBtn');
    downloadBtn.onclick = function () {
      const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(registration.proofBundle, null, 2));
      const downloadAnchor = document.createElement('a');
      downloadAnchor.setAttribute('href', dataStr);
      downloadAnchor.setAttribute('download', 'proof-' + registration.batch.batch_id + '-leaf' + registration.proofBundle.leaf_index + '.json');
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    };

    registerActionBtn.textContent = 'Document Registered';
  });

  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

})();
