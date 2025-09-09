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

    // Dashboard elements
    const searchInput = document.getElementById('searchInput');
    const searchIconBtn = document.getElementById('searchIconBtn');
    const cardsGrid = document.getElementById('cardsGrid');
    const emptyState = document.getElementById('emptyState');
    const cardModal = document.getElementById('cardModal');
    const closeModalBtn = document.getElementById('closeModalBtn');
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
        } else {
            decryptBtnText.textContent = 'Decrypt Data';
            decryptBtnSpinner.classList.add('hidden');
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
        decryptDataSection.classList.remove('hidden');
        dashboardSection.classList.add('hidden');
        jsonSection.classList.add('hidden');
    }

    function showDashboardView() {
        decryptDataSection.classList.add('hidden');
        dashboardSection.classList.remove('hidden');
        jsonSection.classList.add('hidden');
    }

    function showJsonView() {
        decryptDataSection.classList.add('hidden');
        dashboardSection.classList.add('hidden');
        jsonSection.classList.remove('hidden');
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
        backToDecryptBtn.addEventListener('click', showDecryptView);
    }

    if (showJsonBtn) {
        showJsonBtn.addEventListener('click', function() {
            if (decryptedData) {
                showJsonView();
            }
        });
    }

    if (backToDecryptBtnFromJson) {
        backToDecryptBtnFromJson.addEventListener('click', showDecryptView);
    }

    if (showDashboardBtn) {
        showDashboardBtn.addEventListener('click', showDashboardView);
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
            openCardModal(card);
        });

        return cardContainer;
    }

    function openCardModal(card) {
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

            // Auto-select the first record
            const firstRecordElement = recordsList.querySelector('.record-item');
            if (firstRecordElement) {
                // Add active state to first record
                firstRecordElement.classList.remove('bg-white', 'dark:bg-gray-700', 'border-gray-200', 'dark:border-gray-600');
                firstRecordElement.classList.add('bg-purple-50', 'dark:bg-purple-900/30', 'border-purple-200', 'dark:border-purple-700');
                // Show content for first record
                showRecordContent(records[0]);
            } else {
                // Show default content if no records
                showDefaultRecordContent();
            }
        }

        // Show modal
        cardModal.classList.remove('hidden');
    }

    function createRecordElement(record, index) {
        const recordElement = document.createElement('div');
        recordElement.className = 'record-item p-3 bg-white dark:bg-gray-700 border border-gray-200 dark:border-gray-600 rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-600 transition-colors';
        recordElement.innerHTML = `
            <h4 class="font-medium text-gray-900 dark:text-white text-sm">${escapeHtml(record.title || 'Untitled Record')}</h4>
            <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">
                ${Array.isArray(record.data) ? record.data.length : 0} section(s)
            </p>
        `;

        recordElement.addEventListener('click', function() {
            // Remove active state from other records
            recordsList.querySelectorAll('.record-item').forEach(item => {
                item.classList.remove('bg-purple-50', 'dark:bg-purple-900/30', 'border-purple-200', 'dark:border-purple-700');
                item.classList.add('bg-white', 'dark:bg-gray-700', 'border-gray-200', 'dark:border-gray-600');
            });

            // Add active state to clicked record
            recordElement.classList.remove('bg-white', 'dark:bg-gray-700', 'border-gray-200', 'dark:border-gray-600');
            recordElement.classList.add('bg-purple-50', 'dark:bg-purple-900/30', 'border-purple-200', 'dark:border-purple-700');

            showRecordContent(record);
        });

        return recordElement;
    }

    function showDefaultRecordContent() {
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
                        const isSecret = value.type === 'secret';
                        const actualValue = value.value || '';
                        const displayValue = isSecret ? '••••••••' : actualValue;
                        const iconClass = isSecret ? 'text-red-500' : 'text-blue-500';
                        const icon = isSecret ?
                            '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>' :
                            '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>';

                        const uniqueId = `value-${sectionIndex}-${valueIndex}`;
                        // Label based on the type: "Secret" or "Note"
                        const itemLabel = isSecret ? 'Secret' : 'Note';

                        content += `
                            <div class="flex items-start space-x-3">
                                <svg class="w-4 h-4 ${iconClass} mt-1 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    ${icon}
                                </svg>
                                <div class="flex-1 min-w-0">
                                    <div class="flex items-center space-x-2 mb-1">
                                        <p class="text-sm font-medium text-gray-900 dark:text-white">${escapeHtml(value.label || itemLabel)}</p>
                                        <div class="flex items-center space-x-1">
                                            ${isSecret ? `
                                                <button onclick="toggleSecretVisibility('${uniqueId}', '${escapeJavaScript(actualValue)}', this)" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors" title="Show/Hide">
                                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path class="eye-open" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                                                        <path class="eye-open" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>
                                                    </svg>
                                                </button>
                                            ` : ''}
                                            <button onclick="copyToClipboardValue('${escapeJavaScript(actualValue)}', this)" class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors" title="Copy to clipboard">
                                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path class="copy-icon" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path>
                                                </svg>
                                            </button>
                                        </div>
                                    </div>
                                    <p id="${uniqueId}" class="text-sm text-gray-600 dark:text-gray-300 break-all">${escapeHtml(displayValue)}</p>
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

    // Modal event listeners
    if (closeModalBtn) {
        closeModalBtn.addEventListener('click', function() {
            cardModal.classList.add('hidden');
        });
    }

    // Close modal when clicking backdrop
    if (cardModal) {
        cardModal.addEventListener('click', function(e) {
            if (e.target === cardModal || e.target.classList.contains('modal-backdrop')) {
                cardModal.classList.add('hidden');
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
});