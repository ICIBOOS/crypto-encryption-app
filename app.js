// ==========================================
// APPLICATION LOGIC
// ==========================================

let currentMode = 'ecb';
let currentText = '';
let currentKey = '';

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    setupEventListeners();
    updateModeInfo();
});

// ==================== EVENT LISTENERS ====================

function setupEventListeners() {
    // Mode Selection
    document.querySelectorAll('.mode-btn').forEach(btn => {
        btn.addEventListener('click', () => selectMode(btn.dataset.mode));
    });

    // Input Type Selection
    document.querySelectorAll('.input-type-btn').forEach(btn => {
        btn.addEventListener('click', () => switchInputType(btn.dataset.type));
    });

    // Text Input
    const plaintextEl = document.getElementById('plaintext');
    plaintextEl.addEventListener('input', () => {
        currentText = plaintextEl.value;
        document.getElementById('char-count').textContent = currentText.length;
    });

    // File Upload
    const fileDropArea = document.getElementById('file-drop-area');
    const fileInput = document.getElementById('file-input-element');

    fileDropArea.addEventListener('click', () => fileInput.click());
    fileDropArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        fileDropArea.style.background = 'rgba(102, 126, 234, 0.2)';
    });
    fileDropArea.addEventListener('dragleave', () => {
        fileDropArea.style.background = 'rgba(102, 126, 234, 0.05)';
    });
    fileDropArea.addEventListener('drop', (e) => {
        e.preventDefault();
        const files = e.dataTransfer.files;
        if (files.length > 0) handleFileUpload(files[0]);
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) handleFileUpload(e.target.files[0]);
    });

    // Key Input
    const keyEl = document.getElementById('encryption-key');
    keyEl.addEventListener('input', () => {
        currentKey = keyEl.value;
        document.getElementById('key-length').textContent = currentKey.length;
    });

    // Generate Key
    document.getElementById('generate-key-btn').addEventListener('click', () => {
        const newKey = cryptoEngine.generateRandomKey(32);
        keyEl.value = newKey;
        currentKey = newKey;
        document.getElementById('key-length').textContent = newKey.length;
        showMessage('🔑 Kunci berhasil di-generate!', 'success');
    });

    // Encrypt/Decrypt
    document.getElementById('encrypt-btn').addEventListener('click', encrypt);
    document.getElementById('decrypt-btn').addEventListener('click', decrypt);
    document.getElementById('clear-btn').addEventListener('click', clearAll);

    // Output
    document.getElementById('copy-btn').addEventListener('click', copyResult);
    document.getElementById('download-btn').addEventListener('click', downloadResult);
}

// ==================== MODE & INPUT ====================

function selectMode(mode) {
    currentMode = mode;
    document.querySelectorAll('.mode-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.mode === mode);
    });
    updateModeInfo();
    showMessage(`✅ Mode ${mode.toUpperCase()} dipilih!`, 'success');
}

function switchInputType(type) {
    document.querySelectorAll('.input-type-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.type === type);
    });

    document.getElementById('text-input').classList.toggle('active', type === 'text');
    document.getElementById('file-input').classList.toggle('active', type === 'file');
}

function handleFileUpload(file) {
    if (!file.name.endsWith('.txt')) {
        showMessage('❌ Hanya file .txt yang diizinkan!', 'error');
        return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
        currentText = e.target.result;
        document.getElementById('char-count').textContent = currentText.length;
        document.getElementById('file-name').textContent = `📄 File: ${file.name} (${currentText.length} karakter)`;
        showMessage('✅ File berhasil dimuat!', 'success');
    };
    reader.readAsText(file);
}

// ==================== ENCRYPTION & DECRYPTION ====================

function encrypt() {
    if (!currentText || currentText.length < 3) {
        showMessage('❌ Minimal 3 karakter!', 'error');
        return;
    }
    if (!currentKey) {
        showMessage('❌ Masukkan kunci enkripsi!', 'error');
        return;
    }

    showLoading();
    setTimeout(() => {
        try {
            let result;
            if (currentMode === 'ecb') {
                result = cryptoEngine.encryptECB(currentText, currentKey);
            } else {
                result = cryptoEngine.encryptCBC(currentText, currentKey);
            }

            const format = document.getElementById('output-format').value;
            const formatted = formatOutput(result.ciphertext, format);

            document.getElementById('result').value = formatted;
            displayProcessSteps(result.steps);
            showMessage('✅ Enkripsi berhasil!', 'success');
        } catch (error) {
            showMessage('❌ Error: ' + error.message, 'error');
        }
    }, 500);
}

function decrypt() {
    if (!document.getElementById('result').value) {
        showMessage('❌ Tidak ada ciphertext untuk didekripsi!', 'error');
        return;
    }
    if (!currentKey) {
        showMessage('❌ Masukkan kunci dekripsi!', 'error');
        return;
    }

    showLoading();
    setTimeout(() => {
        try {
            let ciphertext = document.getElementById('result').value;
            const format = document.getElementById('output-format').value;

            if (format === 'hex') {
                ciphertext = cryptoEngine.fromHex(ciphertext);
            } else if (format === 'base64') {
                ciphertext = cryptoEngine.fromBase64(ciphertext);
            }

            let result;
            if (currentMode === 'ecb') {
                result = cryptoEngine.decryptECB(ciphertext, currentKey);
            } else {
                result = cryptoEngine.decryptCBC(ciphertext, currentKey);
            }

            document.getElementById('result').value = result.plaintext;
            displayProcessSteps(result.steps);
            showMessage('✅ Dekripsi berhasil!', 'success');
        } catch (error) {
            showMessage('❌ Error: ' + error.message, 'error');
        }
    }, 500);
}

function clearAll() {
    document.getElementById('plaintext').value = '';
    document.getElementById('result').value = '';
    document.getElementById('char-count').textContent = '0';
    document.getElementById('process-details').style.display = 'none';
    showMessage('🧹 Semua data dihapus!', 'success');
}

// ==================== HELPERS ====================

function formatOutput(data, format) {
    if (format === 'hex') {
        return cryptoEngine.toHex(data);
    } else if (format === 'binary') {
        return cryptoEngine.toBinary(data);
    } else if (format === 'base64') {
        return cryptoEngine.toBase64(data);
    }
    return data;
}

function displayProcessSteps(steps) {
    const container = document.getElementById('process-details');
    const stepsEl = document.getElementById('process-steps');
    stepsEl.innerHTML = '';
    steps.forEach(step => {
        const div = document.createElement('div');
        div.textContent = step;
        stepsEl.appendChild(div);
    });
    container.style.display = 'block';
}

function copyResult() {
    const result = document.getElementById('result').value;
    if (!result) {
        showMessage('❌ Tidak ada hasil untuk dicopy!', 'error');
        return;
    }
    navigator.clipboard.writeText(result);
    showMessage('✅ Hasil dicopy ke clipboard!', 'success');
}

function downloadResult() {
    const result = document.getElementById('result').value;
    if (!result) {
        showMessage('❌ Tidak ada hasil untuk didownload!', 'error');
        return;
    }
    const blob = new Blob([result], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `encryption_${new Date().getTime()}.txt`;
    a.click();
    showMessage('✅ File berhasil didownload!', 'success');
}

function showMessage(msg, type) {
    const container = document.getElementById('message-container');
    container.innerHTML = `<div class="${type}-message">${msg}</div>`;
    setTimeout(() => {
        container.innerHTML = '';
    }, 4000);
}

function showLoading() {
    document.getElementById('result').value = '⏳ Loading...';
}

function updateModeInfo() {
    const infoTitle = document.getElementById('info-title');
    const infoContent = document.getElementById('info-content');

    if (currentMode === 'ecb') {
        infoTitle.innerHTML = '📦 Mode ECB (Electronic CodeBook)';
        infoContent.innerHTML = `
            <p><strong>Cara Kerja:</strong></p>
            <ul>
                <li>Setiap block plaintext dienkripsi secara independen</li>
                <li>Menggunakan kombinasi 3 metode:</li>
            </ul>
            <p><strong>Metode yang digunakan:</strong></p>
            <ul>
                <li>🔀 <strong>Substitusi</strong> - Mengganti byte dengan nilai dari S-Box</li>
                <li>🔁 <strong>Permutasi</strong> - Mengubah urutan bit/byte</li>
                <li>↻ <strong>Rotasi</strong> - Merotasi bit berdasarkan kunci</li>
            </ul>
            <p><strong>Keunggulan:</strong> Sederhana dan cepat</p>
            <p><strong>Kelemahan:</strong> Pola plaintext bisa terlihat di ciphertext</p>
        `;
    } else {
        infoTitle.innerHTML = '🔗 Mode CBC (Cipher Block Chaining)';
        infoContent.innerHTML = `
            <p><strong>Cara Kerja:</strong></p>
            <ul>
                <li>Setiap block ciphertext bergantung pada block sebelumnya</li>
                <li>Menggunakan kombinasi 4 metode:</li>
            </ul>
            <p><strong>Metode yang digunakan:</strong></p>
            <ul>
                <li>⚙️ <strong>Feistel Network</strong> - Struktur iteratif untuk keamanan</li>
                <li>🔀 <strong>Substitusi</strong> - Mengganti byte dengan nilai dari S-Box</li>
                <li>🔁 <strong>Permutasi</strong> - Mengubah urutan bit/byte</li>
                <li>XOR Chaining - Menggabungkan dengan block sebelumnya</li>
            </ul>
            <p><strong>Keunggulan:</strong> Lebih aman, pola plaintext tersembunyi</p>
            <p><strong>Kelemahan:</strong> Lebih lambat dan kompleks</p>
        `;
    }
}
