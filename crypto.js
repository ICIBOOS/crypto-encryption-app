// ==========================================
// CRYPTO ENGINE - ECB & CBC MODE
// ==========================================

class CryptoEngine {
    constructor() {
        // S-Box untuk substitusi (256 nilai)
        this.sBox = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
            0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            // ... (bisa diperpanjang untuk keamanan lebih)
        ].concat(Array(256).fill(0).map((_, i) => (i * 7 + 13) % 256));

        // P-Box untuk permutasi
        this.pBox = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];

        this.blockSize = 8; // 8 bytes per block
    }

    // ==================== ECB MODE ====================
    encryptECB(plaintext, key) {
        const steps = [];
        const keyBytes = this.keyToBytes(key);
        
        steps.push(`1️⃣ Plain text: "${plaintext}" (${plaintext.length} karakter)`);
        steps.push(`2️⃣ Kunci: "${key}" (hashed ke ${keyBytes.length} bytes)`);

        // Padding jika perlu
        let data = this.pad(plaintext);
        steps.push(`3️⃣ Setelah padding: ${data.length} bytes`);

        let ciphertext = '';
        for (let i = 0; i < data.length; i += this.blockSize) {
            const block = data.substring(i, i + this.blockSize);
            steps.push(`4️⃣ Processing block ${Math.floor(i / this.blockSize) + 1}: "${block}"`);
            
            // Substitusi
            let substituted = this.substitute(block, keyBytes);
            steps.push(`   └─ Substitusi: ${substituted.substring(0, 16)}...`);

            // Permutasi
            let permuted = this.permute(substituted);
            steps.push(`   └─ Permutasi: ${permuted.substring(0, 16)}...`);

            // Rotasi
            let rotated = this.rotate(permuted, keyBytes);
            steps.push(`   └─ Rotasi: ${rotated.substring(0, 16)}...`);

            ciphertext += rotated;
        }

        steps.push(`5️⃣ Cipher text selesai (${ciphertext.length} karakter)`);
        return { ciphertext, steps };
    }

    decryptECB(ciphertext, key) {
        const steps = [];
        const keyBytes = this.keyToBytes(key);
        
        steps.push(`1️⃣ Cipher text: ${ciphertext.substring(0, 20)}... (${ciphertext.length} karakter)`);

        let plaintext = '';
        for (let i = 0; i < ciphertext.length; i += this.blockSize * 2) {
            const block = ciphertext.substring(i, i + this.blockSize * 2);
            steps.push(`2️⃣ Processing block ${Math.floor(i / (this.blockSize * 2)) + 1}`);

            // Reverse Rotasi
            let unrotated = this.unrotate(block, keyBytes);
            steps.push(`   └─ Reverse Rotasi`);

            // Reverse Permutasi
            let unpermuted = this.unpermute(unrotated);
            steps.push(`   └─ Reverse Permutasi`);

            // Reverse Substitusi
            let unsubstituted = this.unsubstitute(unpermuted, keyBytes);
            steps.push(`   └─ Reverse Substitusi`);

            plaintext += unsubstituted;
        }

        plaintext = this.unpad(plaintext);
        steps.push(`3️⃣ Plain text recovered: "${plaintext}"`);
        return { plaintext, steps };
    }

    // ==================== CBC MODE ====================
    encryptCBC(plaintext, key) {
        const steps = [];
        const keyBytes = this.keyToBytes(key);
        const iv = this.generateIV();

        steps.push(`1️⃣ Plain text: "${plaintext}"`);
        steps.push(`2️⃣ Initialization Vector (IV): ${iv.substring(0, 16)}...`);
        steps.push(`3️⃣ Kunci: "${key}"`);

        let data = this.pad(plaintext);
        let previousBlock = iv;
        let ciphertext = '';

        for (let i = 0; i < data.length; i += this.blockSize) {
            const block = data.substring(i, i + this.blockSize);
            steps.push(`4️⃣ Block ${Math.floor(i / this.blockSize) + 1}: "${block}"`);

            // XOR dengan previous ciphertext block
            let xored = this.xor(block, previousBlock);
            steps.push(`   └─ XOR dengan previous block`);

            // Feistel Network
            let feisteled = this.feistelNetwork(xored, keyBytes, 2);
            steps.push(`   └─ Feistel Network (2 rounds)`);

            // Substitusi
            let substituted = this.substitute(feisteled, keyBytes);
            steps.push(`   └─ Substitusi`);

            // Permutasi
            let encrypted = this.permute(substituted);
            steps.push(`   └─ Permutasi`);

            ciphertext += encrypted;
            previousBlock = encrypted;
        }

        const result = iv + ciphertext;
        steps.push(`5️⃣ Final ciphertext (dengan IV): ${result.length} karakter`);
        return { ciphertext: result, steps };
    }

    decryptCBC(ciphertext, key) {
        const steps = [];
        const keyBytes = this.keyToBytes(key);

        const iv = ciphertext.substring(0, this.blockSize * 2);
        const actualCiphertext = ciphertext.substring(this.blockSize * 2);

        steps.push(`1️⃣ Extract IV: ${iv.substring(0, 16)}...`);
        steps.push(`2️⃣ Kunci: "${key}"`);

        let plaintext = '';
        let previousBlock = iv;

        for (let i = 0; i < actualCiphertext.length; i += this.blockSize * 2) {
            const block = actualCiphertext.substring(i, i + this.blockSize * 2);
            steps.push(`3️⃣ Block ${Math.floor(i / (this.blockSize * 2)) + 1}`);

            // Reverse Permutasi
            let unpermuted = this.unpermute(block);
            steps.push(`   └─ Reverse Permutasi`);

            // Reverse Substitusi
            let unsubstituted = this.unsubstitute(unpermuted, keyBytes);
            steps.push(`   └─ Reverse Substitusi`);

            // Reverse Feistel
            let unfeisteled = this.feistelNetwork(unsubstituted, keyBytes, 2);
            steps.push(`   └─ Reverse Feistel Network`);

            // XOR dengan previous block
            let decrypted = this.xor(unfeisteled, previousBlock);
            steps.push(`   └─ XOR dengan previous block`);

            plaintext += decrypted;
            previousBlock = block;
        }

        plaintext = this.unpad(plaintext);
        steps.push(`4️⃣ Plain text: "${plaintext}"`);
        return { plaintext, steps };
    }

    // ==================== HELPER FUNCTIONS ====================

    // Konversi key ke bytes
    keyToBytes(key) {
        let bytes = [];
        for (let i = 0; i < key.length; i++) {
            bytes.push(key.charCodeAt(i) & 0xFF);
        }
        return bytes;
    }

    // Substitusi menggunakan S-Box
    substitute(data, keyBytes) {
        let result = '';
        for (let i = 0; i < data.length; i++) {
            const byte = data.charCodeAt(i);
            const sBoxIndex = (byte + keyBytes[i % keyBytes.length]) % 256;
            const substituted = this.sBox[sBoxIndex];
            result += String.fromCharCode(substituted);
        }
        return result;
    }

    // Reverse Substitusi
    unsubstitute(data, keyBytes) {
        let result = '';
        for (let i = 0; i < data.length; i++) {
            const byte = data.charCodeAt(i);
            const sBoxIndex = this.sBox.indexOf(byte);
            const original = (sBoxIndex - keyBytes[i % keyBytes.length] + 256) % 256;
            result += String.fromCharCode(original);
        }
        return result;
    }

    // Permutasi
    permute(data) {
        let result = '';
        for (let i = 0; i < data.length; i += 16) {
            const block = data.substring(i, i + 16).padEnd(16, '\0');
            let permuted = '';
            for (let j = 0; j < 16; j++) {
                const idx = this.pBox[j % this.pBox.length];
                if (idx < block.length) {
                    permuted += block[idx];
                }
            }
            result += permuted;
        }
        return result;
    }

    // Reverse Permutasi
    unpermute(data) {
        let result = '';
        for (let i = 0; i < data.length; i += 16) {
            const block = data.substring(i, i + 16);
            let unpermuted = new Array(16).fill('\0');
            for (let j = 0; j < Math.min(this.pBox.length, block.length); j++) {
                const idx = this.pBox[j];
                if (idx < unpermuted.length) {
                    unpermuted[idx] = block[j];
                }
            }
            result += unpermuted.join('');
        }
        return result;
    }

    // Rotasi
    rotate(data, keyBytes) {
        const rotAmount = keyBytes[0] % 8;
        let result = '';
        for (let i = 0; i < data.length; i++) {
            const byte = data.charCodeAt(i);
            const rotated = ((byte << rotAmount) | (byte >> (8 - rotAmount))) & 0xFF;
            result += String.fromCharCode(rotated);
        }
        return result;
    }

    // Reverse Rotasi
    unrotate(data, keyBytes) {
        const rotAmount = keyBytes[0] % 8;
        let result = '';
        for (let i = 0; i < data.length; i++) {
            const byte = data.charCodeAt(i);
            const unrotated = ((byte >> rotAmount) | (byte << (8 - rotAmount))) & 0xFF;
            result += String.fromCharCode(unrotated);
        }
        return result;
    }

    // Feistel Network
    feistelNetwork(data, keyBytes, rounds) {
        let left = data.substring(0, data.length / 2);
        let right = data.substring(data.length / 2);

        for (let r = 0; r < rounds; r++) {
            const f = this.feistelFunction(right, keyBytes);
            const newRight = this.xor(left, f);
            left = right;
            right = newRight;
        }

        return right + left;
    }

    // Fungsi F untuk Feistel
    feistelFunction(data, keyBytes) {
        let result = '';
        for (let i = 0; i < data.length; i++) {
            const byte = data.charCodeAt(i);
            const keyByte = keyBytes[i % keyBytes.length];
            result += String.fromCharCode((byte * 3 + keyByte) & 0xFF);
        }
        return result;
    }

    // XOR operation
    xor(data1, data2) {
        let result = '';
        const len = Math.max(data1.length, data2.length);
        for (let i = 0; i < len; i++) {
            const byte1 = data1.charCodeAt(i) || 0;
            const byte2 = data2.charCodeAt(i) || 0;
            result += String.fromCharCode(byte1 ^ byte2);
        }
        return result;
    }

    // Padding
    pad(data) {
        const padLen = this.blockSize - (data.length % this.blockSize);
        return data + String.fromCharCode(padLen).repeat(padLen);
    }

    // Unpadding
    unpad(data) {
        const padLen = data.charCodeAt(data.length - 1);
        return data.substring(0, data.length - padLen);
    }

    // Generate random IV
    generateIV() {
        let iv = '';
        for (let i = 0; i < this.blockSize; i++) {
            iv += String.fromCharCode(Math.floor(Math.random() * 256));
        }
        return iv;
    }

    // Konversi ke HEX
    toHex(data) {
        let hex = '';
        for (let i = 0; i < data.length; i++) {
            const byte = data.charCodeAt(i).toString(16).padStart(2, '0');
            hex += byte;
        }
        return hex;
    }

    // Konversi dari HEX
    fromHex(hex) {
        let data = '';
        for (let i = 0; i < hex.length; i += 2) {
            const byte = parseInt(hex.substr(i, 2), 16);
            data += String.fromCharCode(byte);
        }
        return data;
    }

    // Konversi ke Binary
    toBinary(data) {
        let binary = '';
        for (let i = 0; i < data.length; i++) {
            binary += data.charCodeAt(i).toString(2).padStart(8, '0');
        }
        return binary;
    }

    // Konversi ke Base64
    toBase64(data) {
        return btoa(data);
    }

    // Konversi dari Base64
    fromBase64(data) {
        return atob(data);
    }

    // Generate random key
    generateRandomKey(length = 32) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
        let key = '';
        for (let i = 0; i < length; i++) {
            key += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return key;
    }
}

// Export untuk digunakan
const cryptoEngine = new CryptoEngine();
