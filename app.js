// CONFIGURATION
const ITERATIONS = 1000000;
const DB_NAME = "nulKeyDB";
const STORE_NAME = "vault";

let currentPassword = "";
let timerInterval = null;
let saltSelection = [];
let hasPasskey = false;

// Attach event listeners to the window and elements
window.addEventListener('load', async () => {
    await checkPasskeyStatus();

    // Restore last username
    const db = await getDB();
    const tx = db.transaction(STORE_NAME, 'readonly');
    const lastUser = await new Promise(r => {
        const req = tx.objectStore(STORE_NAME).get('last_username');
        req.onsuccess = () => r(req.result);
    });
    if (lastUser) document.getElementById('username').value = lastUser;

    // PWA Service Worker Registration
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('sw.js');
    }
});

window.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        generatePassword();
    }
});

// UI Event Listeners
document.getElementById('domain').addEventListener('input', (e) => {
    e.target.value = e.target.value.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].trim();
});

document.getElementById('username').addEventListener('input', (e) => {
    e.target.value = e.target.value.toLowerCase().trim();
});

['domain', 'username'].forEach(id => {
    document.getElementById(id).addEventListener('focus', (e) => {
        if (e.target.value) e.target.value = '';
    });
});

document.getElementById('pwLength').addEventListener('change', (e) => {
     let val = parseInt(e.target.value);
     if (val < 4) e.target.value = 4;
     if (val > 128) e.target.value = 128;
});

// Expose functions to the global scope for inline event handlers (though we should ideally migrate those too)
// To comply with strict CSP, we'll attach them manually here.
document.getElementById('unlockBtn').onclick = () => unlockMaster();
document.getElementById('passkeyActionBtn').onclick = () => togglePasskeyAction();
document.getElementById('advancedToggle').onclick = () => toggleAdvanced();
document.getElementById('generateBtn').onclick = () => generatePassword();
document.getElementById('output').onclick = () => copyToClipboard();

// Salt buttons
document.querySelectorAll('.salt-btn').forEach(btn => {
    btn.onclick = () => {
        const char = btn.textContent;
        toggleSalt(btn, char);
    };
});

async function checkPasskeyStatus() {
    const db = await getDB();
    const tx = db.transaction(STORE_NAME, 'readonly');
    const saved = await new Promise(r => {
        const req = tx.objectStore(STORE_NAME).get('master_vault');
        req.onsuccess = () => r(req.result);
    });

    const btn = document.getElementById('passkeyActionBtn');
    const unlockBtn = document.getElementById('unlockBtn');

    if (saved) {
        hasPasskey = true;
        btn.textContent = "Disable Passkey";
        btn.style.background = "rgba(220, 38, 38, 0.2)";
        btn.style.color = "#f87171";
        btn.style.borderColor = "rgba(220, 38, 38, 0.3)";
        unlockBtn.style.display = 'block';
        document.getElementById('masterPwdContainer').style.display = 'none';
        document.getElementById('saltKeypadContainer').style.display = 'none';

        // Clear salt selection when in passkey mode to avoid confusion
        saltSelection = [];
        document.querySelectorAll('.salt-btn').forEach(b => b.classList.remove('selected'));
    } else {
        hasPasskey = false;
        btn.textContent = "Enable Passkey";
        btn.style.background = "rgba(56, 189, 248, 0.1)";
        btn.style.color = "var(--accent)";
        btn.style.borderColor = "rgba(56, 189, 248, 0.2)";
        unlockBtn.style.display = 'none';
        document.getElementById('masterPwdContainer').style.display = 'block';
        document.getElementById('saltKeypadContainer').style.display = 'flex';
    }
}

async function togglePasskeyAction() {
    if (hasPasskey) {
        await disablePasskey();
    } else {
        const master = document.getElementById('masterPwd').value;
        if (!master || saltSelection.length !== 4) {
            alert("Enter Master Password and select 4 symbols first to enable Passkey.");
            return;
        }
        await saveMaster(master, saltSelection);
    }
    await checkPasskeyStatus();
}

async function disablePasskey() {
    if (!confirm("Are you sure you want to disable and remove the Passkey?")) return;

    try {
        const db = await getDB();
        const tx = db.transaction(STORE_NAME, 'readwrite');
        await new Promise((resolve, reject) => {
            const req = tx.objectStore(STORE_NAME).delete('master_vault');
            req.onsuccess = resolve;
            req.onerror = reject;
        });

        // Clear internal state
        saltSelection = [];
        document.querySelectorAll('.salt-btn').forEach(btn => btn.classList.remove('selected'));
        document.getElementById('masterPwd').value = "";
        document.getElementById('masterPwd').placeholder = "";
        document.getElementById('masterPwd').disabled = false;

        // Reset Unlock Button State
        const unlockBtn = document.getElementById('unlockBtn');
        unlockBtn.textContent = "Unlock with Biometrics";
        unlockBtn.style.color = "";
        unlockBtn.style.borderColor = "";

        // Close advanced options to show the change
        toggleAdvanced();

    } catch (err) {
        console.error(err);
        alert("Failed to remove passkey: " + err.message);
    }
}

function toggleSalt(btn, char) {
    const index = saltSelection.indexOf(char);

    if (index > -1) {
        saltSelection.splice(index, 1);
        btn.classList.remove('selected');
    } else {
        if (saltSelection.length < 4) {
            saltSelection.push(char);
            btn.classList.add('selected');
        } else {
            const keypad = document.querySelector('.salt-keypad');
            keypad.style.transform = "translateX(5px)";
            setTimeout(() => keypad.style.transform = "translateX(0)", 100);
            setTimeout(() => keypad.style.transform = "translateX(-5px)", 200);
            setTimeout(() => keypad.style.transform = "translateX(0)", 300);
        }
    }
}

const getDB = () => new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = (e) => e.target.result.createObjectStore(STORE_NAME);
    request.onsuccess = (e) => resolve(e.target.result);
    request.onerror = (e) => reject(e.target.error);
});

async function getEncryptionKey(prfResults) {
    const input = prfResults.results.first;
    return await window.crypto.subtle.importKey(
        "raw", input, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
    );
}

async function encryptData(key, data) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv }, key, encoder.encode(JSON.stringify(data))
    );
    return { iv: btoa(String.fromCharCode(...iv)), ciphertext: btoa(String.fromCharCode(...new Uint8Array(encrypted))) };
}

async function decryptData(key, vault) {
    const iv = new Uint8Array(atob(vault.iv).split('').map(c => c.charCodeAt(0)));
    const ciphertext = new Uint8Array(atob(vault.ciphertext).split('').map(c => c.charCodeAt(0)));
    const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv }, key, ciphertext
    );
    return JSON.parse(new TextDecoder().decode(decrypted));
}

async function unlockMaster() {
    try {
        const db = await getDB();
        const tx = db.transaction(STORE_NAME, 'readonly');
        const vault = await new Promise(r => {
            const req = tx.objectStore(STORE_NAME).get('master_vault');
            req.onsuccess = () => r(req.result);
        });

        if (!vault) return null;

        const challenge = window.crypto.getRandomValues(new Uint8Array(32));
        const assertion = await navigator.credentials.get({
            publicKey: {
                challenge,
                allowCredentials: [{ type: 'public-key', id: vault.credId }],
                userVerification: 'required',
                extensions: {
                    prf: { eval: { first: new Uint8Array(32).fill(1) } }
                }
            }
        });

        const extensionResults = assertion.getClientExtensionResults();
        if (extensionResults.prf) {
            const key = await getEncryptionKey(extensionResults.prf);
            const data = await decryptData(key, vault);

            const unlockBtn = document.getElementById('unlockBtn');
            if (unlockBtn) {
                unlockBtn.textContent = "Authenticated";
                unlockBtn.style.color = "#FFD700";
                unlockBtn.style.borderColor = "#FFD700";
            }

            return data;
        } else {
            throw new Error("Authenticator did not provide PRF output.");
        }
    } catch (err) {
        console.error(err);
        if (err.name !== 'NotAllowedError') alert("Biometric unlock failed: " + err.message);
        return null;
    }
}

async function saveMaster(pwd, salt) {
    try {
        if (!window.isSecureContext) {
            throw new Error("Biometrics require a secure context (HTTPS or localhost).");
        }

        const challenge = window.crypto.getRandomValues(new Uint8Array(32));
        const rp = { name: "nulKey" };
        const hostname = window.location.hostname;
        if (hostname && hostname !== "localhost") {
            rp.id = hostname;
        }

        const userId = window.crypto.getRandomValues(new Uint8Array(16));

        const credential = await navigator.credentials.create({
            publicKey: {
                challenge,
                rp: rp,
                user: {
                    id: userId,
                    name: "user-" + Date.now(),
                    displayName: "nulKey User"
                },
                pubKeyCredParams: [{ alg: -7, type: "public-key" }],
                authenticatorSelection: {
                    userVerification: "required",
                    residentKey: "required",
                    requireResidentKey: true
                },
                extensions: {
                    prf: { eval: { first: new Uint8Array(32).fill(1) } }
                }
            }
        });

        const extensionResults = credential.getClientExtensionResults();
        if (!extensionResults.prf || !extensionResults.prf.enabled) {
            throw new Error("Your browser/device does not support the WebAuthn PRF extension required for secure biometric storage.");
        }

        let prfResult = extensionResults.prf;
        
        const key = await getEncryptionKey(prfResult);
        const { iv, ciphertext } = await encryptData(key, { p: pwd, s: salt });

        const db = await getDB();
        const tx = db.transaction(STORE_NAME, 'readwrite');
        tx.objectStore(STORE_NAME).put({
            credId: credential.rawId,
            iv,
            ciphertext
        }, 'master_vault');

        alert("Passkey enabled successfully.");
    } catch (err) {
        console.error(err);
        alert("Failed to enable passkey: " + err.message);
    }
}

async function generatePassword() {
    let master = document.getElementById('masterPwd').value;
    const domain = document.getElementById('domain').value.toLowerCase().trim();
    const user = document.getElementById('username').value.toLowerCase().trim();
    const count = document.getElementById('counter').value;

    const length = parseInt(document.getElementById('pwLength').value) || 14;
    const useUpper = document.getElementById('useUpper').checked;
    const useLower = document.getElementById('useLower').checked;
    const useNumbers = document.getElementById('useNumbers').checked;
    const useSpecial = document.getElementById('useSpecial').checked;

    let salts = [...saltSelection];

    if (hasPasskey && !master) {
        const data = await unlockMaster();
        if (!data) return;
        master = data.p;
        salts = data.s || [];
    }

    if (!master || !domain) return alert("Missing Master Password or Domain");
    if (salts.length !== 4) return alert("Please select 4 Secret Pattern symbols");
    if (!useUpper && !useLower && !useNumbers && !useSpecial) return alert("Select at least one character type");

    const db = await getDB();
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).put(user, 'last_username');

    const btn = document.getElementById('generateBtn');
    btn.disabled = true;
    btn.textContent = "Hashing...";

    const userSalt = [...salts].sort().join('');
    const saltStr = `${userSalt}${user}${domain}${count}`;
    const encoder = new TextEncoder();

    const baseKey = await window.crypto.subtle.importKey(
        "raw", encoder.encode(master), "PBKDF2", false, ["deriveBits"]
    );

    master = null;

    const derivedBits = await window.crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: encoder.encode(saltStr),
            iterations: ITERATIONS,
            hash: "SHA-256"
        },
        baseKey,
        Math.max(length * 32, 1024)
    );

    const hashArray = new Uint8Array(derivedBits);
    currentPassword = formatPassword(hashArray, length, { useUpper, useLower, useNumbers, useSpecial });

    showResult();
    btn.disabled = false;
    btn.textContent = "Generate Password";

    if (hasPasskey) {
        const unlockBtn = document.getElementById('unlockBtn');
        if (unlockBtn) {
            unlockBtn.textContent = "Unlock with Biometrics";
            unlockBtn.style.color = "";
            unlockBtn.style.borderColor = "";
        }
        document.querySelectorAll('.salt-btn').forEach(b => b.classList.remove('selected'));
        saltSelection = [];
    }
}

function formatPassword(bytes, length, opts) {
    const sets = [];
    if (opts.useUpper) sets.push("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    if (opts.useLower) sets.push("abcdefghijklmnopqrstuvwxyz");
    if (opts.useNumbers) sets.push("0123456789");
    if (opts.useSpecial) sets.push("!@#$%^&*_-.");

    if (sets.length === 0) return "";

    const targetLength = Math.max(length, sets.length);
    const allChars = sets.join("");
    let res = [];
    let byteIdx = 0;

    for (let i = 0; i < sets.length; i++) {
        const set = sets[i];
        res.push(set[bytes[byteIdx++] % set.length]);
    }

    while (res.length < targetLength) {
        res.push(allChars[bytes[byteIdx++] % allChars.length]);
    }

    for (let i = res.length - 1; i > 0; i--) {
        const j = bytes[byteIdx++] % (i + 1);
        [res[i], res[j]] = [res[j], res[i]];
    }

    return res.slice(0, length).join("");
}

function showResult() {
    const area = document.getElementById('resultArea');
    const out = document.getElementById('output');
    area.style.display = 'block';
    out.textContent = currentPassword;

    let seconds = 60;
    const timer = document.getElementById('timer');
    timer.textContent = seconds;

    if (timerInterval) clearInterval(timerInterval);
    timerInterval = setInterval(() => {
        seconds--;
        timer.textContent = seconds;
        if (seconds <= 0) {
            clearResult();
        }
    }, 1000);
}

function clearResult() {
    clearInterval(timerInterval);
    document.getElementById('resultArea').style.display = 'none';
    document.getElementById('output').textContent = "";
    currentPassword = "";
    try { navigator.clipboard.writeText(""); } catch(e) {}
}

function copyToClipboard() {
    navigator.clipboard.writeText(currentPassword);
    const out = document.getElementById('output');
    const originalText = out.textContent;
    out.textContent = "COPIED!";
    setTimeout(() => out.textContent = originalText, 1000);
}

function toggleAdvanced() {
    const el = document.getElementById('advancedOptions');
    const btn = document.getElementById('advancedToggle');
    const icon = document.getElementById('advancedToggleIcon');
    if (el.style.display === 'none') {
        el.style.display = 'block';
        btn.style.color = 'var(--accent)';
        btn.style.borderColor = 'var(--accent)';
        btn.style.background = 'rgba(56, 189, 248, 0.1)';
        if (icon) icon.style.opacity = '1';
    } else {
        el.style.display = 'none';
        btn.style.color = '#94a3b8';
        btn.style.borderColor = 'var(--glass-border)';
        btn.style.background = 'rgba(255,255,255,0.05)';
        if (icon) icon.style.opacity = '0.6';
    }
}
