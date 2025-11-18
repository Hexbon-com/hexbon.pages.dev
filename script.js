// Crypto utilities (embedded from the existing app)
(function () {
    'use strict';

    const VERSION = 'v1';
    const PBKDF2_ITERATIONS = 150000;
    const PBKDF2_HASH = 'SHA-256';
    const SALT_BYTES = 16;
    const IV_BYTES = 12;

    const te = new TextEncoder();
    const td = new TextDecoder();

    function getRandomBytes(len) {
        const buf = new Uint8Array(len);
        crypto.getRandomValues(buf);
        return buf;
    }

    function bytesToBase64(bytes) {
        let binary = '';
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) binary += String.fromCharCode(bytes[i]);
        return btoa(binary);
    }

    function base64ToBytes(base64) {
        const binary = atob(base64);
        const len = binary.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
        return bytes;
    }

    async function deriveAesGcmKey(password, saltBytes) {
        const baseKey = await crypto.subtle.importKey(
            'raw',
            te.encode(password),
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );

        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                hash: PBKDF2_HASH,
                salt: saltBytes,
                iterations: PBKDF2_ITERATIONS,
            },
            baseKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    async function encrypt(plainText, password) {
        if (!plainText && plainText !== '') throw new Error('Plaintext required');
        if (!password) throw new Error('Password required');

        const salt = getRandomBytes(SALT_BYTES);
        const iv = getRandomBytes(IV_BYTES);
        const key = await deriveAesGcmKey(password, salt);

        const cipherBuf = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            te.encode(plainText)
        );

        const payload = [
            VERSION,
            bytesToBase64(salt),
            bytesToBase64(iv),
            bytesToBase64(new Uint8Array(cipherBuf)),
        ].join(':');

        return payload;
    }

    async function decrypt(payload, password) {
        if (!payload) throw new Error('Payload required');
        if (!password) throw new Error('Password required');

        const parts = String(payload).split(':');
        if (parts.length !== 4) throw new Error('Invalid payload format');
        const [ver, saltB64, ivB64, ctB64] = parts;
        if (ver !== VERSION) throw new Error('Unsupported version');

        const salt = base64ToBytes(saltB64);
        const iv = base64ToBytes(ivB64);
        const ct = base64ToBytes(ctB64);

        const key = await deriveAesGcmKey(password, salt);
        const plainBuf = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            ct
        );
        return td.decode(plainBuf);
    }

    async function encryptDashboardJson(jsonData, hexRefKey, rk) {
        if (!jsonData) throw new Error('JSON data required');
        if (!hexRefKey) throw new Error('Reference key required');
        if (!rk) throw new Error('RK salt required');

        const jsonString = typeof jsonData === 'string' ? jsonData : JSON.stringify(jsonData);
        const combinedKey = hexRefKey + ':' + rk;
        return await encrypt(jsonString, combinedKey);
    }

    async function decryptDashboardJson(encryptedPayload, hexRefKey, rk) {
        if (!encryptedPayload) throw new Error('Encrypted payload required');
        if (!hexRefKey) throw new Error('Reference key required');
        if (!rk) throw new Error('RK salt required');

        const combinedKey = hexRefKey + ':' + rk;
        const decryptedString = await decrypt(encryptedPayload, combinedKey);
        return JSON.parse(decryptedString);
    }

    const Api = { encrypt, decrypt, encryptDashboardJson, decryptDashboardJson, VERSION };

    if (typeof window !== 'undefined') {
        window.CryptoUtil = Api;
    }
})();

// TOTP Generation Logic
async function generateTOTP(secretBase32) {
    const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    function base32Decode(str) {
        str = str.replace(/=+$/g, '').toUpperCase();
        const bytes = [];
        let bits = 0, value = 0;
        for (let i = 0; i < str.length; i++) {
            const idx = base32Alphabet.indexOf(str[i]);
            if (idx === -1) continue;
            value = (value << 5) | idx;
            bits += 5;
            if (bits >= 8) {
                bytes.push((value >>> (bits - 8)) & 0xFF);
                bits -= 8;
            }
        }
        return new Uint8Array(bytes);
    }

    function intToBytes(num) {
        const buf = new ArrayBuffer(8);
        const view = new DataView(buf);
        const high = Math.floor(num / 0x100000000);
        const low = num >>> 0;
        view.setUint32(0, high);
        view.setUint32(4, low);
        return new Uint8Array(buf);
    }

    async function hmacSHA1(key, data) {
        const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
        const sig = await crypto.subtle.sign('HMAC', k, data);
        return new Uint8Array(sig);
    }

    function pad(num, size = 6) {
        return num.toString().padStart(size, '0');
    }

    try {
        const secret = base32Decode(secretBase32);
        const step = 30;
        const counter = Math.floor(Date.now() / 1000 / step);
        const hmac = await hmacSHA1(secret, intToBytes(counter));
        const offset = hmac[hmac.length - 1] & 0x0f;
        const code = ((hmac[offset] & 0x7f) << 24 |
                     (hmac[offset + 1] & 0xff) << 16 |
                     (hmac[offset + 2] & 0xff) << 8 |
                     (hmac[offset + 3] & 0xff)) % 1_000_000;

        return pad(code);
    } catch (error) {
        console.error('TOTP generation error:', error);
        return 'ERROR';
    }
}

function getTOTPTimeRemaining() {
    const now = Math.floor(Date.now() / 1000);
    const step = 30;
    return step - (now % step);
}

// Main application logic
document.addEventListener('DOMContentLoaded', function() {
    // DOM elements
    const encryptionKeyInput = document.getElementById('encryptionKey');
    const encryptedInput = document.getElementById('encryptedInput');
    const rkInput = document.getElementById('rkInput');
    const decryptBtn = document.getElementById('decryptBtn');
    const decryptBtnText = document.getElementById('decryptBtnText');
    const decryptBtnSpinner = document.getElementById('decryptBtnSpinner');
    const toggleKeyVisibility = document.getElementById('toggleKeyVisibility');
    const eyeIcon = document.getElementById('eyeIcon');
    const eyeSlashIcon = document.getElementById('eyeSlashIcon');
    const errorMessage = document.getElementById('errorMessage');
    const errorText = document.getElementById('errorText');
    const darkModeToggle = document.getElementById('darkModeToggle');

    // Sections
    const decryptDataSection = document.getElementById('decrypt-data-section');
    const dashboardSection = document.getElementById('dashboard-section');
    const jsonSection = document.getElementById('json-section');
    const backToDecryptBtn = document.getElementById('backToDecryptBtn');
    const showJsonBtn = document.getElementById('showJsonBtn');
    const backToDecryptBtnFromJson = document.getElementById('backToDecryptBtnFromJson');
    const showDashboardBtn = document.getElementById('showDashboardBtn');
    const copyJsonBtn = document.getElementById('copyJsonBtn');
    const jsonDisplay = document.getElementById('jsonDisplay');

    // Mobile JSON bottom bar elements
    const mobileJsonBottomBar = document.getElementById('mobileJsonBottomBar');
    const mobileJsonBackToDecrypt = document.getElementById('mobileJsonBackToDecrypt');
    const mobileJsonShowDashboard = document.getElementById('mobileJsonShowDashboard');
    const mobileJsonCopy = document.getElementById('mobileJsonCopy');
    const jsonScrollToTopBtn = document.getElementById('jsonScrollToTopBtn');

    // Dashboard elements
    const searchInput = document.getElementById('searchInput');
    const searchIconBtn = document.getElementById('searchIconBtn');
    const cardsGrid = document.getElementById('cardsGrid');
    const emptyState = document.getElementById('emptyState');
    const cardModal = document.getElementById('cardModal');
    const closeModalBtn = document.getElementById('closeModalBtn');
    // New detail section
    const cardDetailSection = document.getElementById('card-detail-section');
    const backToDashboardFromCard = document.getElementById('backToDashboardFromCard');
    const backToCardsFromCard = document.getElementById('backToCardsFromCard');
    const modalCardTitle = document.getElementById('modalCardTitle');
    const recordsList = document.getElementById('recordsList');
    const recordContent = document.getElementById('recordContent');
    const searchNoResults = document.getElementById('searchNoResults');
    const searchQueryEcho = document.getElementById('searchQueryEcho');

    // Banner elements
    const readOnlyBanner = document.getElementById('readOnlyBanner');
    const dismissBannerBtn = document.getElementById('dismissBannerBtn');

    // Storage for decrypted data
    let decryptedData = null;

    // Session storage keys
    const STORAGE_KEYS = {
        encryptedKey: 'hexbon:encryptedKey', // encryption key encrypted with RK
        encryptedData: 'hexbon:encryptedData', // the pasted encrypted JSON payload
    };

    // Helpers to manage session-stored secrets
    function clearSessionStoredSecrets() {
        try { sessionStorage.removeItem(STORAGE_KEYS.encryptedKey); } catch {}
        try { sessionStorage.removeItem(STORAGE_KEYS.encryptedData); } catch {}
    }

    // Helper: scroll window to top immediately (no animation)
    function scrollToTopImmediate() {
        try { window.scrollTo(0, 0); } catch {}
    }

    // Helper to reset app state, clear session, and navigate back to decrypt page
    function clearAllDataAndGoHome() {
        // Clear stored secrets
        clearSessionStoredSecrets();

        // Reset UI inputs and state
        try {
            if (encryptionKeyInput) encryptionKeyInput.value = '';
            if (encryptedInput) encryptedInput.value = '';
            if (jsonDisplay) jsonDisplay.value = '';
            if (cardsGrid) cardsGrid.innerHTML = '';
        } catch {}

        decryptedData = null;
        hideError();
        showDecryptView();
        scrollToTopImmediate();
    }

    // Safely update button text label while preserving icons
    function setButtonLabel(button, newText) {
        if (!button) return;
        const spans = button.getElementsByTagName('span');
        if (spans && spans.length) {
            spans[spans.length - 1].textContent = newText;
        } else {
            // Fallback if there is no span wrapper
            button.textContent = newText;
        }
        button.setAttribute('aria-label', newText);
        button.setAttribute('title', newText);
    }

    // Try to auto-decrypt from session on page load (requires RK present in the form)
    async function attemptAutoDecryptFromSession() {
        try {
            if (!window.CryptoUtil) return false; // crypto not ready

            const storedEncKey = sessionStorage.getItem(STORAGE_KEYS.encryptedKey);
            const storedPayload = sessionStorage.getItem(STORAGE_KEYS.encryptedData);
            if (!storedEncKey || !storedPayload) return false; // nothing to do

            const rk = (rkInput?.value || '').trim();
            if (!rk) return false; // cannot decrypt the key without RK; wait until user provides it

            // First, decrypt the encryption key using RK
            let recoveredKey;
            try {
                recoveredKey = await window.CryptoUtil.decrypt(storedEncKey, rk);
            } catch (e) {
                // Bad RK or corrupted stored key; wipe
                clearSessionStoredSecrets();
                return false;
            }

            // Validate payload format before attempting decryption
            if (!(storedPayload.includes(':') && storedPayload.split(':').length === 4)) {
                clearSessionStoredSecrets();
                return false;
            }

            // Decrypt the stored payload into the dashboard JSON
            try {
                const data = await window.CryptoUtil.decryptDashboardJson(storedPayload, recoveredKey, rk);
                decryptedData = data;

                // Populate inputs and views
                if (encryptionKeyInput) encryptionKeyInput.value = recoveredKey;
                if (encryptedInput) encryptedInput.value = storedPayload;
                if (jsonDisplay) jsonDisplay.value = JSON.stringify(data, null, 2);

                renderDashboard(decryptedData);
                showDashboardView();
                return true;
            } catch (e) {
                // Decryption failed (bad pair of key/payload); wipe session
                clearSessionStoredSecrets();
                return false;
            }
        } catch (e) {
            // Any unexpected error: be safe and clear
            clearSessionStoredSecrets();
            return false;
        }
    }

    // Dark mode toggle
    if (darkModeToggle) {
        darkModeToggle.addEventListener('click', function() {
            const isDark = document.documentElement.classList.contains('dark');
            if (isDark) {
                document.documentElement.classList.remove('dark');
                localStorage.setItem('theme', 'light');
                document.documentElement.style.backgroundColor = '#ffffff';
            } else {
                document.documentElement.classList.add('dark');
                localStorage.setItem('theme', 'dark');
                document.documentElement.style.backgroundColor = '#111827';
            }

            // Ensure icons update immediately after toggle
            const sun = document.getElementById('sunIcon');
            const moon = document.getElementById('moonIcon');
            if (sun && moon) {
                const nowDark = document.documentElement.classList.contains('dark');
                // Show sun in dark mode, show moon in light mode
                sun.classList.toggle('hidden', !nowDark);
                moon.classList.toggle('hidden', nowDark);
            }
        });

        // Sync icons on initial load
        const sunInit = document.getElementById('sunIcon');
        const moonInit = document.getElementById('moonIcon');
        if (sunInit && moonInit) {
            const isDarkNow = document.documentElement.classList.contains('dark');
            // Show sun in dark mode, show moon in light mode
            sunInit.classList.toggle('hidden', !isDarkNow);
            moonInit.classList.toggle('hidden', isDarkNow);
        }
    }

    // Toggle password visibility
    if (toggleKeyVisibility) {
        toggleKeyVisibility.addEventListener('click', function() {
            const isPassword = encryptionKeyInput.type === 'password';
            encryptionKeyInput.type = isPassword ? 'text' : 'password';
            eyeIcon.classList.toggle('hidden', !isPassword);
            eyeSlashIcon.classList.toggle('hidden', isPassword);
        });
    }

    // Toggle RK section visibility
    const toggleRkVisibility = document.getElementById('toggleRkVisibility');
    const rkSection = document.getElementById('rkSection');
    const rkCaretDownIcon = document.getElementById('rkCaretDownIcon');
    const rkCaretUpIcon = document.getElementById('rkCaretUpIcon');
    const rkLabel = document.getElementById('rkLabel');

    function toggleRkSection() {
        const isHidden = rkSection.classList.contains('hidden');
        rkSection.classList.toggle('hidden', !isHidden);
        rkCaretDownIcon.classList.toggle('hidden', isHidden);
        rkCaretUpIcon.classList.toggle('hidden', !isHidden);
    }

    if (toggleRkVisibility && rkSection) {
        toggleRkVisibility.addEventListener('click', toggleRkSection);
    }

    // Make Reference Key label clickable too
    if (rkLabel && rkSection) {
        rkLabel.addEventListener('click', toggleRkSection);
    }

    // Banner dismiss functionality
    if (dismissBannerBtn && readOnlyBanner) {
        dismissBannerBtn.addEventListener('click', function() {
            readOnlyBanner.style.display = 'none';
            // Save preference to localStorage so it stays dismissed
            localStorage.setItem('readOnlyBannerDismissed', 'true');
        });

        // Check if banner was previously dismissed
        if (localStorage.getItem('readOnlyBannerDismissed') === 'true') {
            readOnlyBanner.style.display = 'none';
        }
    }

    // Utility functions
    function escapeHtml(unsafe) {
        if (unsafe == null) return '';
        return String(unsafe)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    function escapeJavaScript(unsafe) {
        if (unsafe == null) return '';
        return String(unsafe)
            .replace(/\\/g, "\\\\")
            .replace(/'/g, "\\'")
            .replace(/"/g, '\\"')
            .replace(/\n/g, "\\n")
            .replace(/\r/g, "\\r")
            .replace(/\t/g, "\\t")
            .replace(/\f/g, "\\f")
            .replace(/\v/g, "\\v")
            .replace(/\0/g, "\\0");
    }

    function formatRelativeTime(timestamp) {
        if (!timestamp) return 'Recently';

        try {
            // Parse the timestamp - handle both Unix timestamps (seconds/milliseconds) and ISO strings
            let date;
            if (typeof timestamp === 'string') {
                // Try to parse as ISO string first
                date = new Date(timestamp);
                // If invalid, try parsing as number
                if (isNaN(date.getTime())) {
                    const num = parseFloat(timestamp);
                    if (!isNaN(num)) {
                        // Assume seconds if less than typical millisecond timestamp
                        date = new Date(num < 10000000000 ? num * 1000 : num);
                    }
                }
            } else if (typeof timestamp === 'number') {
                // Assume seconds if less than typical millisecond timestamp
                date = new Date(timestamp < 10000000000 ? timestamp * 1000 : timestamp);
            } else {
                return 'Recently';
            }

            // Check if date is valid
            if (isNaN(date.getTime())) {
                return 'Recently';
            }

            const now = new Date();
            const diffMs = now.getTime() - date.getTime();
            const diffSeconds = Math.floor(diffMs / 1000);

            if (diffSeconds < 0) {
                return 'Recently'; // Future dates
            }

            if (diffSeconds < 60) {
                return diffSeconds <= 1 ? '1 second ago' : `${diffSeconds} seconds ago`;
            }

            const diffMinutes = Math.floor(diffSeconds / 60);
            if (diffMinutes < 60) {
                return diffMinutes === 1 ? '1 minute ago' : `${diffMinutes} minutes ago`;
            }

            const diffHours = Math.floor(diffMinutes / 60);
            if (diffHours < 24) {
                return diffHours === 1 ? '1 hour ago' : `${diffHours} hours ago`;
            }

            const diffDays = Math.floor(diffHours / 24);
            if (diffDays < 7) {
                return diffDays === 1 ? '1 day ago' : `${diffDays} days ago`;
            }

            const diffWeeks = Math.floor(diffDays / 7);
            if (diffWeeks < 4) {
                return diffWeeks === 1 ? '1 week ago' : `${diffWeeks} weeks ago`;
            }

            const diffMonths = Math.floor(diffDays / 30);
            if (diffMonths < 12) {
                return diffMonths === 1 ? '1 month ago' : `${diffMonths} months ago`;
            }

            const diffYears = Math.floor(diffDays / 365);
            return diffYears === 1 ? '1 year ago' : `${diffYears} years ago`;

        } catch (error) {
            return 'Recently';
        }
    }

    function showError(message) {
        errorText.textContent = message;
        errorMessage.classList.remove('hidden');
    }

    function hideError() {
        errorMessage.classList.add('hidden');
    }

    function setLoading(isLoading) {
        decryptBtn.disabled = isLoading;
        if (isLoading) {
            decryptBtnText.textContent = 'Decrypting...';
            decryptBtnSpinner.classList.remove('hidden');
            decryptBtnSpinner.classList.add('inline-block');
        } else {
            decryptBtnText.textContent = 'Decrypt Data';
            decryptBtnSpinner.classList.add('hidden');
            decryptBtnSpinner.classList.remove('inline-block');
        }
    }

    async function copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch (err) {
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            try {
                document.execCommand('copy');
                document.body.removeChild(textArea);
                return true;
            } catch (err) {
                document.body.removeChild(textArea);
                return false;
            }
        }
    }

    // Switch between decrypt, dashboard, and JSON views
    function showDecryptView() {
        stopTOTPUpdates();
        decryptDataSection.classList.remove('hidden');
        dashboardSection.classList.add('hidden');
        jsonSection.classList.add('hidden');
        hideMobileBottomBar();
        hideMobileDashboardBottomBar();
        hideMobileJsonBottomBar();
    }

    function showDashboardView() {
        stopTOTPUpdates();
        decryptDataSection.classList.add('hidden');
        dashboardSection.classList.remove('hidden');
        jsonSection.classList.add('hidden');
        hideMobileBottomBar();
        hideMobileJsonBottomBar();
        // Show dashboard bottom bar on mobile
        if (isMobile() && mobileDashboardBottomBar) {
            mobileDashboardBottomBar.classList.remove('hidden');
        }
    }

    function showJsonView() {
        stopTOTPUpdates();
        decryptDataSection.classList.add('hidden');
        dashboardSection.classList.add('hidden');
        jsonSection.classList.remove('hidden');
        hideMobileBottomBar();
        hideMobileDashboardBottomBar();
        // Show mobile JSON bottom bar on mobile
        if (isMobile() && mobileJsonBottomBar) {
            mobileJsonBottomBar.classList.remove('hidden');
        }
    }

    // Main decrypt function
    async function performDecryption() {
        hideError();
        setLoading(true);

        try {
            const encryptionKey = encryptionKeyInput.value.trim();
            const encryptedData = encryptedInput.value.trim();
            const rk = rkInput.value.trim();

            if (!encryptionKey) {
                showError('Please enter your encryption key.');
                return;
            }

            if (!encryptedData) {
                showError('Please paste your encrypted JSON data.');
                return;
            }

            if (!rk) {
                showError('Please enter your reference key (RK).');
                return;
            }

            if (!window.CryptoUtil) {
                showError('Crypto utilities not loaded. Please refresh the page.');
                return;
            }

            // Check if the data looks like encrypted format
            if (encryptedData.includes(':') && encryptedData.split(':').length === 4) {
                try {
                    const decrypted = await window.CryptoUtil.decryptDashboardJson(encryptedData, encryptionKey, rk);

                    // Store decrypted data for both dashboard and JSON views
                    decryptedData = decrypted;

                    // On successful decryption, persist to sessionStorage
                    try {
                        // Encrypt the user-provided encryption key using RK as the password
                        const encryptedKeyForSession = await window.CryptoUtil.encrypt(encryptionKey, rk);
                        sessionStorage.setItem(STORAGE_KEYS.encryptedKey, encryptedKeyForSession);
                        // Store the encrypted JSON payload exactly as pasted
                        sessionStorage.setItem(STORAGE_KEYS.encryptedData, encryptedData);
                    } catch (persistErr) {
                        console.warn('Unable to persist session data:', persistErr);
                    }

                    // Format JSON for JSON view
                    const formattedJson = JSON.stringify(decrypted, null, 2);
                    if (jsonDisplay) {
                        jsonDisplay.value = formattedJson;
                    }

                    // Go directly to dashboard view
                    renderDashboard(decryptedData);
                    showDashboardView();

                } catch (error) {
                    showError('Decryption failed');
                }
            } else {
                showError('Invalid encrypted data format.');
            }

        } catch (error) {
            console.error('Decryption error:', error);
            showError('Decryption failed');
        } finally {
            setLoading(false);
        }
    }

    // Event listeners for decrypt view
    if (decryptBtn) {
        decryptBtn.addEventListener('click', performDecryption);
    }

    // Navigation event listeners
    if (backToDecryptBtn) {
        setButtonLabel(backToDecryptBtn, 'Clear Data');
        backToDecryptBtn.addEventListener('click', clearAllDataAndGoHome);
    }

    if (showJsonBtn) {
        showJsonBtn.addEventListener('click', function() {
            if (decryptedData) {
                showJsonView();
            }
        });
    }

    if (backToDecryptBtnFromJson) {
        setButtonLabel(backToDecryptBtnFromJson, 'Clear Data');
        backToDecryptBtnFromJson.addEventListener('click', clearAllDataAndGoHome);
    }

    if (showDashboardBtn) {
        showDashboardBtn.addEventListener('click', showDashboardView);
    }

    // If RK changes and we have session data, try to auto-decrypt
    if (rkInput) {
        rkInput.addEventListener('change', attemptAutoDecryptFromSession);
    }

    if (copyJsonBtn) {
        copyJsonBtn.addEventListener('click', async function() {
            if (jsonDisplay && jsonDisplay.value) {
                const success = await copyToClipboard(jsonDisplay.value);
                if (success) {
                    const originalContent = copyJsonBtn.innerHTML;
                    copyJsonBtn.innerHTML = '<svg class="w-4 h-4 mr-2 inline-block text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>Copied!';
                    setTimeout(() => {
                        copyJsonBtn.innerHTML = originalContent;
                    }, 700);
                }
            }
        });
    }

    // Mobile JSON bottom bar event handlers
    if (mobileJsonBackToDecrypt) {
        setButtonLabel(mobileJsonBackToDecrypt, 'Clear Data');
        mobileJsonBackToDecrypt.addEventListener('click', clearAllDataAndGoHome);
    }

    if (mobileJsonShowDashboard) {
        mobileJsonShowDashboard.addEventListener('click', showDashboardView);
    }

    if (mobileJsonCopy) {
        mobileJsonCopy.addEventListener('click', async function() {
            if (jsonDisplay && jsonDisplay.value) {
                try {
                    await navigator.clipboard.writeText(jsonDisplay.value);
                    const originalContent = mobileJsonCopy.innerHTML;
                    mobileJsonCopy.innerHTML = '<div class="w-8 h-8 flex items-center justify-center mb-1"><svg class="w-6 h-6 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg></div><span>Copied!</span>';
                    setTimeout(() => {
                        mobileJsonCopy.innerHTML = originalContent;
                    }, 700);
                } catch (err) {
                    console.error('Failed to copy JSON:', err);
                }
            }
        });
    }

    // Auto-clear data when inputs change
    [encryptionKeyInput, encryptedInput, rkInput].forEach(function(input) {
        if (input) {
            input.addEventListener('input', function() {
                hideError();
                decryptedData = null;
                if (jsonDisplay) {
                    jsonDisplay.value = '';
                }
            });
        }
    });

    // Enter key handler for inputs
    [encryptionKeyInput, encryptedInput, rkInput].forEach(function(input) {
        if (input) {
            input.addEventListener('keydown', function(event) {
                if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) {
                    performDecryption();
                }
            });
        }
    });

    // Dashboard functionality
    function renderDashboard(data) {
        // Clear previous content
        cardsGrid.innerHTML = '';

        // Ensure we have a cards array
        const cards = Array.isArray(data?.cards) ? data.cards :
                     (data?.cards && typeof data.cards === 'object') ? Object.values(data.cards) : [];

        if (cards.length === 0) {
            emptyState.classList.remove('hidden');
            return;
        } else {
            emptyState.classList.add('hidden');
        }

        // Render cards
        cards.forEach((card, index) => {
            const cardElement = createCardElement(card, index);
            cardsGrid.appendChild(cardElement);
        });
    }

    function createCardElement(card, index) {
        const cardContainer = document.createElement('div');
        cardContainer.className = 'card-container relative w-72';
        cardContainer.setAttribute('data-card-id', index);

        // Count records and sections
        const records = Array.isArray(card.records) ? card.records :
                       (card.records && typeof card.records === 'object') ? Object.values(card.records) : [];
        const recordCount = records.length;
        let sectionCount = 0;

        records.forEach(record => {
            if (Array.isArray(record.data)) {
                sectionCount += record.data.length;
            }
        });

        cardContainer.innerHTML = `
            <div class="card-item bg-white/80 dark:bg-gray-800/80 backdrop-blur-lg border border-gray-200 dark:border-gray-700 rounded-2xl p-6 cursor-pointer hover:shadow-xl transition-all duration-300">
                <div class="flex flex-col h-48">
                    <h3 class="card-title text-lg font-semibold text-gray-900 dark:text-white mb-2 text-center pt-8 line-clamp-2">${escapeHtml(card.title || card.name || 'Untitled Card')}</h3>
                    <p class="text-sm text-gray-600 dark:text-gray-300 flex-1 text-center card-counts">
                        <span class="card-counts-records">Contains ${recordCount} record(s)</span>
                        <span class="block card-counts-sections">and ${sectionCount} section(s)</span>
                    </p>
                    <div class="flex items-center justify-center mt-4">
                        <div class="text-center">
                            <span class="text-xs text-gray-400 dark:text-gray-500 block">Last updated</span>
                            <span class="text-xs text-gray-500 dark:text-gray-400">${escapeHtml(formatRelativeTime(card.updated_at))}</span>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Store card data reference
        cardContainer.__cardDataRef = card;

        // Add click event to open modal
        cardContainer.addEventListener('click', function() {
            // Always scroll to top before navigating into a card
            scrollToTopImmediate();
            openCardModal(card);
        });

        return cardContainer;
    }

    function openCardModal(card) {
        // For backward compatibility: if modal exists, use it. Otherwise open detail section.
        if (cardDetailSection) {
            openCardDetail(card);
            return;
        }

        modalCardTitle.textContent = card.title || card.name || 'Untitled Card';

        // Clear and populate records list
        recordsList.innerHTML = '';

        const records = Array.isArray(card.records) ? card.records :
                       (card.records && typeof card.records === 'object') ? Object.values(card.records) : [];

        if (records.length === 0) {
            recordsList.innerHTML = '<p class="text-gray-500 dark:text-gray-400 text-sm">No records available</p>';
            // Show default content
            showDefaultRecordContent();
        } else {
            records.forEach((record, index) => {
                const recordElement = createRecordElement(record, index);
                recordsList.appendChild(recordElement);
            });

            // Auto-select the first record on desktop only; on mobile, don't preselect
            const firstRecordElement = recordsList.querySelector('.record-item');
            if (firstRecordElement) {
                if (!isMobile()) {
                    // Add active state to first record (desktop)
                    firstRecordElement.classList.remove('bg-white', 'dark:bg-gray-700', 'border-gray-200', 'dark:border-gray-600');
                    firstRecordElement.classList.add('bg-purple-50', 'dark:bg-purple-900/30', 'border-purple-200', 'dark:border-purple-700');
                    // Show content for first record
                    showRecordContent(records[0]);
                } else {
                    // Mobile: don't auto-select; show default panel content
                    showDefaultRecordContent();
                }
            } else {
                // Show default content if no records
                showDefaultRecordContent();
            }
        }

        // Show modal if present
        if (cardModal) cardModal.classList.remove('hidden');
    }

    // New: open card detail as full view
    function openCardDetail(card) {
        // Set title/subtitle
        modalCardTitle.textContent = card.title || card.name || 'Untitled Card';
        const subtitle = (card.description || card.subtitle || '');
        const modalCardSubtitle = document.getElementById('modalCardSubtitle');
        if (modalCardSubtitle) modalCardSubtitle.textContent = subtitle;

        // Populate records list
        recordsList.innerHTML = '';
        const records = Array.isArray(card.records) ? card.records :
                       (card.records && typeof card.records === 'object') ? Object.values(card.records) : [];

        if (records.length === 0) {
            recordsList.innerHTML = '<p class="text-gray-500 dark:text-gray-400 text-sm">No records available</p>';
            showDefaultRecordContent();
        } else {
            records.forEach((record, index) => {
                const recordElement = createRecordElement(record, index);
                recordsList.appendChild(recordElement);
            });

            const firstRecordElement = recordsList.querySelector('.record-item');
            if (firstRecordElement) {
                if (!isMobile()) {
                    firstRecordElement.classList.remove('bg-white', 'dark:bg-gray-700', 'border-gray-200', 'dark:border-gray-600');
                    firstRecordElement.classList.add('bg-purple-50', 'dark:bg-purple-900/30', 'border-purple-200', 'dark:border-purple-700');
                    showRecordContent(records[0]);
                } else {
                    // Mobile: don't auto-select to avoid pre-focusing a record
                    showDefaultRecordContent();
                }
            } else {
                showDefaultRecordContent();
            }
        }

        // Show detail section and hide dashboard
        if (cardDetailSection) {
            dashboardSection.classList.add('hidden');
            cardDetailSection.classList.remove('hidden');
        }
    }

    function createRecordElement(record, index) {
        const recordElement = document.createElement('div');
        recordElement.className = 'record-item p-3 bg-white dark:bg-gray-700 border border-gray-200 dark:border-gray-600 rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-600';
        recordElement.innerHTML = `
            <h4 class="font-medium text-gray-900 dark:text-white text-sm">${escapeHtml(record.title || 'Untitled Record')}</h4>
            <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">
                ${Array.isArray(record.data) ? record.data.length : 0} section(s)
            </p>
        `;

        recordElement.addEventListener('click', function() {
            // Always scroll to top before showing record content
            scrollToTopImmediate();
            // Remove active state from other records
            recordsList.querySelectorAll('.record-item').forEach(item => {
                item.classList.remove('bg-purple-50', 'dark:bg-purple-900/30', 'border-purple-200', 'dark:border-purple-700');
                item.classList.add('bg-white', 'dark:bg-gray-700', 'border-gray-200', 'dark:border-gray-600');
            });

            // Add active state to clicked record
            recordElement.classList.remove('bg-white', 'dark:bg-gray-700', 'border-gray-200', 'dark:border-gray-600');
            recordElement.classList.add('bg-purple-50', 'dark:bg-purple-900/30', 'border-purple-200', 'dark:border-purple-700');

            showRecordContent(record);

            // Mobile: when a record is clicked, hide the records column and show only content
            if (isMobile()) {
                if (recordsColumn) recordsColumn.classList.add('hidden');
                if (contentColumn) contentColumn.classList.remove('hidden');
                // Update mobile bottom bar to show "Back to Records"
                updateMobileBottomBarForRecordView();
            }
        });

        return recordElement;
    }

    // Mobile helpers: determine small screens
    function isMobile() {
        try {
            return window.innerWidth <= 640; // Tailwind's sm breakpoint
        } catch (e) {
            return false;
        }
    }

    // Helper: clear selected/highlight classes from all record items
    function clearRecordSelection() {
        if (!recordsList) return;
        recordsList.querySelectorAll('.record-item').forEach(item => {
            item.classList.remove('bg-purple-50', 'dark:bg-purple-900/30', 'border-purple-200', 'dark:border-purple-700');
            item.classList.add('bg-white', 'dark:bg-gray-700', 'border-gray-200', 'dark:border-gray-600');
        });
    }

    const recordsColumn = document.getElementById('recordsColumn');
    const contentColumn = document.getElementById('contentColumn');
    const backToRecordsBtn = document.getElementById('backToRecordsBtn');

    // Mobile bottom bar elements
    const mobileBottomBar = document.getElementById('mobileBottomBar');
    const mobileBottomBarContent = document.getElementById('mobileBottomBarContent');
    const mobileBackToCards = document.getElementById('mobileBackToCards');
    const scrollToTopBtn = document.getElementById('scrollToTopBtn');

    // Dashboard mobile bottom bar elements
    const mobileDashboardBottomBar = document.getElementById('mobileDashboardBottomBar');
    const mobileDashboardBackToDecrypt = document.getElementById('mobileDashboardBackToDecrypt');
    const mobileDashboardShowJson = document.getElementById('mobileDashboardShowJson');
    const dashboardScrollToTopBtn = document.getElementById('dashboardScrollToTopBtn');
    const showJsonFromCard = document.getElementById('showJsonFromCard');

    // When viewing a card on mobile, show records column first
    function ensureMobileInitialState() {
        if (!cardDetailSection) return;
        if (isMobile()) {
            // Show only records column
            if (recordsColumn) recordsColumn.classList.remove('hidden');
            if (contentColumn) contentColumn.classList.add('hidden');
            // On mobile, ensure no record appears pre-selected
            clearRecordSelection();
            // Show mobile bottom bar with "Back to Cards"
            if (mobileBottomBar) mobileBottomBar.classList.remove('hidden');
            updateMobileBottomBarForCardView();
        } else {
            // On larger screens, show both
            if (recordsColumn) recordsColumn.classList.remove('hidden');
            if (contentColumn) contentColumn.classList.remove('hidden');
            // Hide mobile bottom bar
            if (mobileBottomBar) mobileBottomBar.classList.add('hidden');
        }
    }

    // Update mobile bottom bar content for card view (showing records list)
    function updateMobileBottomBarForCardView() {
        if (!mobileBottomBarContent) return;
        mobileBottomBarContent.innerHTML = `
            <div class="flex w-full">
                <button type="button"
                        id="mobileBackToCards"
                        class="w-1/2 flex flex-col items-center justify-center py-2 px-3 text-gray-600 dark:text-gray-400 font-medium text-xs transition-all duration-200 hover:text-purple-600 dark:hover:text-purple-400 active:scale-95">
                    <div class="w-8 h-8 flex items-center justify-center mb-1">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"></path>
                        </svg>
                    </div>
                    <span>Back to Cards</span>
                </button>
                <!-- Placeholder for consistency -->
                <div class="w-1/2 flex flex-col items-center justify-center py-2 px-3">
                    <!-- Empty space for visual consistency -->
                </div>
            </div>
        `;
        // Re-attach event listeners
        const newBackToCardsBtn = document.getElementById('mobileBackToCards');

        if (newBackToCardsBtn) {
            newBackToCardsBtn.addEventListener('click', function() {
                // Stop TOTP updates
                stopTOTPUpdates();
                // Scroll to top before returning to cards
                scrollToTopImmediate();
                cardDetailSection.classList.add('hidden');
                dashboardSection.classList.remove('hidden');
                hideMobileBottomBar();
                // Show dashboard bottom bar on mobile
                if (isMobile() && mobileDashboardBottomBar) {
                    mobileDashboardBottomBar.classList.remove('hidden');
                }
            });
        }

        if (newScrollToTopBtn) {
            newScrollToTopBtn.addEventListener('click', function() {
                window.scrollTo({ top: 0, behavior: 'smooth' });
            });
        }
    }

    // Update mobile bottom bar content for record view
    function updateMobileBottomBarForRecordView() {
        if (!mobileBottomBarContent) return;
        mobileBottomBarContent.innerHTML = `
            <div class="flex w-full">
                <button type="button"
                        id="mobileBackToRecords"
                        class="w-1/2 flex flex-col items-center justify-center py-2 px-3 text-gray-600 dark:text-gray-400 font-medium text-xs transition-all duration-200 hover:text-purple-600 dark:hover:text-purple-400 active:scale-95">
                    <div class="w-8 h-8 flex items-center justify-center mb-1">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"></path>
                        </svg>
                    </div>
                    <span>Back to Records</span>
                </button>
                <!-- Placeholder for consistency -->
                <div class="w-1/2 flex flex-col items-center justify-center py-2 px-3">
                    <!-- Empty space for visual consistency -->
                </div>
            </div>
        `;
        // Re-attach event listeners
        const newBackToRecordsBtn = document.getElementById('mobileBackToRecords');

        if (newBackToRecordsBtn) {
            newBackToRecordsBtn.addEventListener('click', function() {
                // Scroll to top before returning to records list
                scrollToTopImmediate();
                // Show records list again
                if (recordsColumn) recordsColumn.classList.remove('hidden');
                if (contentColumn) contentColumn.classList.add('hidden');
                // On mobile, remove any selected styling so nothing is pre-highlighted
                if (isMobile()) clearRecordSelection();
                updateMobileBottomBarForCardView();
            });
        }
    }

    if (backToRecordsBtn) {
        backToRecordsBtn.addEventListener('click', function() {
            // Scroll to top before returning to records list
            scrollToTopImmediate();
            // Show records list again
            if (recordsColumn) recordsColumn.classList.remove('hidden');
            if (contentColumn) contentColumn.classList.add('hidden');
            if (isMobile()) clearRecordSelection();
            updateMobileBottomBarForCardView();
        });
    }

    // Whenever detail opens, ensure mobile initial presentation
    const originalOpenCardDetail = window.openCardDetail || null;
    // Wrap openCardDetail to call ensureMobileInitialState if defined locally
    if (typeof openCardDetail === 'function') {
        const orig = openCardDetail;
        openCardDetail = function(card) {
            orig(card);
            // After populating records, enforce mobile-first state
            ensureMobileInitialState();
        };
        // expose back to global if needed
        window.openCardDetail = openCardDetail;
    }

    // Handle window resize to toggle mobile state while open
    window.addEventListener('resize', function() {
        // If detail section visible, adjust columns
        if (cardDetailSection && !cardDetailSection.classList.contains('hidden')) {
            ensureMobileInitialState();
        }

        // If dashboard section visible, adjust bottom bar
        if (dashboardSection && !dashboardSection.classList.contains('hidden')) {
            if (isMobile()) {
                if (mobileDashboardBottomBar) mobileDashboardBottomBar.classList.remove('hidden');
            } else {
                hideMobileDashboardBottomBar();
            }
        }
    });

    // Mobile bottom bar button handlers
    // Note: These are now handled dynamically in updateMobileBottomBarForCardView() and updateMobileBottomBarForRecordView()

    // Wire desktop show JSON button if present
    if (showJsonFromCard) {
        showJsonFromCard.addEventListener('click', function() {
            if (decryptedData) {
                showJsonView();
            }
        });
    }

    // Scroll to top functionality
    if (scrollToTopBtn) {
        scrollToTopBtn.addEventListener('click', function() {
            window.scrollTo({ top: 0, behavior: 'smooth' });
        });
    }

    // Dashboard scroll to top functionality
    if (dashboardScrollToTopBtn) {
        dashboardScrollToTopBtn.addEventListener('click', function() {
            window.scrollTo({ top: 0, behavior: 'smooth' });
        });
    }

    // Dashboard mobile bottom bar button handlers
    if (mobileDashboardBackToDecrypt) {
        setButtonLabel(mobileDashboardBackToDecrypt, 'Clear Data');
        mobileDashboardBackToDecrypt.addEventListener('click', function() {
            clearAllDataAndGoHome();
        });
    }

    if (mobileDashboardShowJson) {
        mobileDashboardShowJson.addEventListener('click', function() {
            if (decryptedData) {
                showJsonView();
            }
        });
    }

    // Show/hide scroll to top button based on scroll position
    function handleScroll() {
        const scrollTop = window.pageYOffset || document.documentElement.scrollTop;

        // For card detail view
        if (cardDetailSection && !cardDetailSection.classList.contains('hidden')) {
            const scrollToTopBtn = document.getElementById('scrollToTopBtn');
            if (scrollToTopBtn) {
                if (scrollTop > 300) {
                    scrollToTopBtn.classList.remove('hidden');
                } else {
                    scrollToTopBtn.classList.add('hidden');
                }
            }
        }

        // For dashboard view
        if (dashboardSection && !dashboardSection.classList.contains('hidden')) {
            if (dashboardScrollToTopBtn) {
                if (scrollTop > 300) {
                    dashboardScrollToTopBtn.classList.remove('hidden');
                } else {
                    dashboardScrollToTopBtn.classList.add('hidden');
                }
            }
        }
    }

    window.addEventListener('scroll', handleScroll);

    // Hide mobile bottom bar when not in card detail view
    function hideMobileBottomBar() {
        if (mobileBottomBar) {
            mobileBottomBar.classList.add('hidden');
        }
        if (scrollToTopBtn) {
            scrollToTopBtn.classList.add('hidden');
        }
    }

    // Hide mobile dashboard bottom bar
    function hideMobileDashboardBottomBar() {
        if (mobileDashboardBottomBar) {
            mobileDashboardBottomBar.classList.add('hidden');
        }
        if (dashboardScrollToTopBtn) {
            dashboardScrollToTopBtn.classList.add('hidden');
        }
    }

    // Hide mobile JSON bottom bar
    function hideMobileJsonBottomBar() {
        if (mobileJsonBottomBar) {
            mobileJsonBottomBar.classList.add('hidden');
        }
        if (jsonScrollToTopBtn) {
            jsonScrollToTopBtn.classList.add('hidden');
        }
    }

    function showDefaultRecordContent() {
        stopTOTPUpdates();
        recordContent.innerHTML = `
            <div class="flex-1 flex items-center justify-center py-16">
                <div class="text-center">
                    <div class="w-16 h-16 bg-gradient-to-tr from-purple-700 to-blue-500 rounded-xl flex items-center justify-center mx-auto mb-4">
                        <svg class="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                        </svg>
                    </div>
                    <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-2">Select a Record</h3>
                    <p class="text-gray-600 dark:text-gray-300">Choose a record from the left panel to view its contents</p>
                </div>
            </div>
        `;
    }

    function showRecordContent(record) {
        const sections = Array.isArray(record.data) ? record.data : [];

        let content = `
            <div class="mb-6">
                <h3 class="text-xl font-bold text-gray-900 dark:text-white mb-2">${escapeHtml(record.title || 'Untitled Record')}</h3>
                <p class="text-sm text-gray-600 dark:text-gray-400">${sections.length} section(s)</p>
            </div>
        `;

        if (sections.length === 0) {
            content += `
                <div class="text-center py-8">
                    <p class="text-gray-500 dark:text-gray-400">No sections available in this record.</p>
                </div>
            `;
        } else {
            content += '<div class="space-y-6">';

            sections.forEach((section, sectionIndex) => {
                const values = Array.isArray(section.values) ? section.values : [];

                // Use the actual section name from the JSON
                const sectionTitle = section.name || section.title || 'Untitled Section';

                content += `
                    <div class="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                        <h4 class="font-semibold text-gray-900 dark:text-white mb-3">${escapeHtml(sectionTitle)}</h4>
                `;

                if (values.length === 0) {
                    content += '<p class="text-sm text-gray-500 dark:text-gray-400">No values in this section.</p>';
                } else {
                    content += '<div class="space-y-3">';

                    values.forEach((value, valueIndex) => {
                        // Only display values that have actual content
                        const actualValue = value.value || '';
                        if (!actualValue.trim()) {
                            return; // Skip empty values
                        }

                        const isSecret = value.type === 'secret';
                        const isTOTP = value.type === 'totp';
                        const displayValue = isSecret ? '••••••••' : (isTOTP ? 'Loading...' : actualValue);
                        const iconClass = isSecret ? 'text-red-500' : (isTOTP ? 'text-green-500' : 'text-blue-500');

                        let icon;
                        if (isSecret) {
                            icon = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>';
                        } else if (isTOTP) {
                            icon = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>';
                        } else {
                            icon = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>';
                        }

                        const uniqueId = `value-${sectionIndex}-${valueIndex}`;
                        // Label based on the type: "Secret", "2FA Code", or "Note"
                        const itemLabel = isSecret ? 'Secret' : (isTOTP ? '2FA Code' : 'Note');

                        content += `
                            <div class="flex items-start space-x-3">
                                <svg class="w-4 h-4 ${iconClass} mt-1 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    ${icon}
                                </svg>
                                <div class="flex-1 min-w-0">
                                    <div class="flex items-center space-x-2 mb-1">
                                        <p class="text-sm font-medium text-gray-900 dark:text-white">${escapeHtml(value.label || itemLabel)}</p>
                                        ${isTOTP ? `
                                            <span id="${uniqueId}-timer" class="text-xs text-gray-500 dark:text-gray-400 font-mono">30s</span>
                                        ` : ''}
                                        <div class="flex items-center space-x-1">
                                            ${isSecret ? `
                                                <button onclick="toggleSecretVisibility('${uniqueId}', '${escapeJavaScript(actualValue)}', this)" class="cursor-pointer text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors" title="Show/Hide">
                                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path class="eye-open" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                                                        <path class="eye-open" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>
                                                    </svg>
                                                </button>
                                            ` : ''}
                                            <button onclick="${isTOTP ? `copyTOTPCode('${uniqueId}', this)` : `copyToClipboardValue('${escapeJavaScript(actualValue)}', this)`}" class="cursor-pointer text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors" title="Copy to clipboard">
                                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path class="copy-icon" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path>
                                                </svg>
                                            </button>
                                        </div>
                                    </div>
                                    <p id="${uniqueId}" class="text-sm ${isTOTP ? 'text-green-600 dark:text-green-400 font-mono text-lg font-semibold tracking-wider' : 'text-gray-600 dark:text-gray-300'} break-all" ${isTOTP ? `data-totp-secret="${escapeHtml(actualValue)}"` : ''}>${escapeHtml(displayValue)}</p>
                                </div>
                            </div>
                        `;
                    });

                    content += '</div>';
                }

                content += '</div>';
            });

            content += '</div>';
        }

        recordContent.innerHTML = content;

        // Start TOTP updates if there are any TOTP fields
        const hasTOTP = recordContent.querySelectorAll('[data-totp-secret]').length > 0;
        if (hasTOTP) {
            startTOTPUpdates();
        }
    }

    // Helper function to toggle secret visibility
    window.toggleSecretVisibility = function(elementId, actualValue, button) {
        const element = document.getElementById(elementId);
        const isHidden = element.textContent === '••••••••';

        if (isHidden) {
            element.textContent = actualValue;
            button.innerHTML = `
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 3l18 18"></path>
                </svg>
            `;
            button.title = "Hide";
        } else {
            element.textContent = '••••••••';
            button.innerHTML = `
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>
                </svg>
            `;
            button.title = "Show";
        }
    };

    // Helper function to copy value to clipboard
    window.copyToClipboardValue = async function(value, button) {
        try {
            await navigator.clipboard.writeText(value);
            showCopySuccessIcon(button);
        } catch (err) {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = value;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            textArea.style.top = '-999999px';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            try {
                document.execCommand('copy');
                showCopySuccessIcon(button);
            } catch (err) {
                console.error('Failed to copy to clipboard:', err);
            }
            document.body.removeChild(textArea);
        }
    };

    // Helper function to copy TOTP code to clipboard
    window.copyTOTPCode = async function(elementId, button) {
        const element = document.getElementById(elementId);
        if (!element) return;

        const code = element.textContent;
        if (code === 'Loading...' || code === 'ERROR') return;

        try {
            await navigator.clipboard.writeText(code);
            showCopySuccessIcon(button);
        } catch (err) {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = code;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            textArea.style.top = '-999999px';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            try {
                document.execCommand('copy');
                showCopySuccessIcon(button);
            } catch (err) {
                console.error('Failed to copy to clipboard:', err);
            }
            document.body.removeChild(textArea);
        }
    };

    // Helper function to show copy success feedback
    function showCopySuccessIcon(button) {
        const originalContent = button.innerHTML;
        button.innerHTML = `
            <svg class="w-4 h-4 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
            </svg>
        `;
        button.title = "Copied!";

        setTimeout(() => {
            button.innerHTML = originalContent;
            button.title = "Copy to clipboard";
        }, 700);
    }

    // TOTP update functionality
    let totpUpdateInterval = null;

    async function updateAllTOTPCodes() {
        const totpElements = document.querySelectorAll('[data-totp-secret]');

        for (const element of totpElements) {
            const secret = element.getAttribute('data-totp-secret');
            if (secret) {
                try {
                    const code = await generateTOTP(secret);
                    element.textContent = code;
                } catch (error) {
                    element.textContent = 'ERROR';
                    console.error('Failed to generate TOTP:', error);
                }
            }
        }
    }

    function updateAllTOTPTimers() {
        const timerElements = document.querySelectorAll('[id$="-timer"]');
        const remaining = getTOTPTimeRemaining();

        timerElements.forEach(timer => {
            timer.textContent = `${remaining}s`;

            // Change color based on remaining time
            if (remaining <= 5) {
                timer.classList.add('text-red-500', 'dark:text-red-400');
                timer.classList.remove('text-gray-500', 'dark:text-gray-400');
            } else {
                timer.classList.remove('text-red-500', 'dark:text-red-400');
                timer.classList.add('text-gray-500', 'dark:text-gray-400');
            }
        });
    }

    function startTOTPUpdates() {
        // Clear any existing interval
        if (totpUpdateInterval) {
            clearInterval(totpUpdateInterval);
        }

        // Initial update
        updateAllTOTPCodes();
        updateAllTOTPTimers();

        // Update every second
        totpUpdateInterval = setInterval(() => {
            const remaining = getTOTPTimeRemaining();
            updateAllTOTPTimers();

            // Regenerate codes when timer resets (at 30 seconds)
            if (remaining === 30) {
                updateAllTOTPCodes();
            }
        }, 1000);
    }

    function stopTOTPUpdates() {
        if (totpUpdateInterval) {
            clearInterval(totpUpdateInterval);
            totpUpdateInterval = null;
        }
    }

    // Modal fallback event listeners (for legacy modal if present)
    if (closeModalBtn && cardModal) {
        closeModalBtn.addEventListener('click', function() {
            cardModal.classList.add('hidden');
        });
    }

    if (cardModal) {
        cardModal.addEventListener('click', function(e) {
            if (e.target === cardModal || e.target.classList.contains('modal-backdrop')) {
                cardModal.classList.add('hidden');
            }
        });
    }

    // Back button from card detail to dashboard
    if (backToDashboardFromCard && cardDetailSection) {
        backToDashboardFromCard.addEventListener('click', function() {
            stopTOTPUpdates();
            cardDetailSection.classList.add('hidden');
            dashboardSection.classList.remove('hidden');
            hideMobileBottomBar();
            // Show dashboard bottom bar on mobile
            if (isMobile() && mobileDashboardBottomBar) {
                mobileDashboardBottomBar.classList.remove('hidden');
            }
        });
    }

    // Back button from card detail to cards (desktop)
    if (backToCardsFromCard && cardDetailSection) {
        backToCardsFromCard.addEventListener('click', function() {
            stopTOTPUpdates();
            cardDetailSection.classList.add('hidden');
            dashboardSection.classList.remove('hidden');
            hideMobileBottomBar();
            // Show dashboard bottom bar on mobile
            if (isMobile() && mobileDashboardBottomBar) {
                mobileDashboardBottomBar.classList.remove('hidden');
            }
        });
    }

    // Search functionality
    function applySearch(query) {
        const normalize = (s) => (s || '').toString().toLowerCase();
        const q = normalize(query);
        const cards = document.querySelectorAll('.card-container');

        let visibleCount = 0;
        cards.forEach(card => {
            let matched = false;

            if (!q) {
                matched = true;
            } else {
                // Card title
                const cardTitle = normalize(card.querySelector('h3')?.textContent);
                if (cardTitle.includes(q)) {
                    matched = true;
                } else {
                    // Search in card data
                    const baseData = card.__cardDataRef;
                    if (baseData) {
                        // Records as array
                        let records = [];
                        if (Array.isArray(baseData.records)) records = baseData.records;
                        else if (baseData.records && typeof baseData.records === 'object') records = Object.values(baseData.records);

                        // Check record titles, section titles, and note values
                        for (const rec of records) {
                            if (!rec) continue;
                            if (normalize(rec.title).includes(q)) { matched = true; break; }

                            const sections = Array.isArray(rec.data) ? rec.data : [];
                            let foundInSections = false;
                            for (const section of sections) {
                                if (!section) continue;
                                // Check multiple possible section title properties
                                const sectionTitle = section.name || section.title || section.label || '';
                                if (normalize(sectionTitle).includes(q)) { matched = true; foundInSections = true; break; }

                                const values = Array.isArray(section.values) ? section.values : [];
                                for (const val of values) {
                                    // Only search note values (type !== 'secret')
                                    if (val && val.type !== 'secret' && normalize(val.value).includes(q)) { matched = true; foundInSections = true; break; }
                                }
                                if (foundInSections) break;
                            }
                            if (matched) break;
                        }
                    }
                }
            }

            card.style.display = matched ? 'block' : 'none';
            if (matched) visibleCount++;
        });

        // Toggle no-results message
        if (searchNoResults && searchQueryEcho) {
            if (q && visibleCount === 0) {
                searchQueryEcho.textContent = searchInput?.value || '';
                searchNoResults.classList.remove('hidden');
            } else {
                searchNoResults.classList.add('hidden');
            }
        }
    }

    function setSearchIconState(hasQuery) {
        const searchIcon = searchIconBtn?.querySelector('.search-icon');
        const clearIcon = searchIconBtn?.querySelector('.clear-icon');

        if (hasQuery) {
            searchIcon?.classList.add('hidden');
            clearIcon?.classList.remove('hidden');
            searchIconBtn?.setAttribute('aria-label', 'Clear search');
        } else {
            clearIcon?.classList.add('hidden');
            searchIcon?.classList.remove('hidden');
            searchIconBtn?.setAttribute('aria-label', 'Search');
        }
    }

    // Search event listeners
    if (searchInput) {
        setSearchIconState(Boolean(searchInput.value));
        applySearch(searchInput.value);

        searchInput.addEventListener('input', function(e) {
            const q = e.target.value.toLowerCase();
            setSearchIconState(Boolean(q));
            applySearch(q);
        });
    }

    if (searchIconBtn && searchInput) {
        searchIconBtn.addEventListener('click', function() {
            const q = searchInput.value.toLowerCase();
            if (q) {
                // Clear search and reset cards
                searchInput.value = '';
                setSearchIconState(false);
                applySearch('');
                searchInput.focus();
            } else {
                // No query: focus input
                searchInput.focus();
            }
        });
    }

    // Initially hide the decrypt form until we decide what to show
    if (decryptDataSection) decryptDataSection.classList.add('hidden');

    // Decide initial view: try session auto-decrypt; otherwise reveal the form
    async function initAutoFlow() {
        try {
            const hasStored = !!(sessionStorage.getItem(STORAGE_KEYS.encryptedKey) && sessionStorage.getItem(STORAGE_KEYS.encryptedData));
            if (hasStored) {
                const success = await attemptAutoDecryptFromSession();
                if (success) {
                    return; // Dashboard shown
                }
            }
        } catch {}
        // No stored data or couldn't decrypt: show form
        showDecryptView();
    }

    // Kick off initial flow (no need to await)
    initAutoFlow();
});