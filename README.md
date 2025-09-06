# Hexbon Decryption Tool

A secure, client-side decryption tool for accessing your <a href="https://hexbon.com" target="_blank">Hexbon.com</a> encrypted data. This tool serves as a redundancy solution to ensure you always have access to your encrypted information, even if the main Hexbon service is unavailable.

**🔐 Security Notice**: Always verify you're using the official hosted versions. Never enter your encryption key on suspicious or unofficial sites.

## Table of Contents

- 🔐 [Overview](#-overview)
- 🌐 [Live Access](#-live-access)
- 🔒 [Privacy & Security](#-privacy--security)
- 🏠 [Local Development](#-local-development)
- 🛡️ [Security Features](#️-security-features)
- 🔧 [How It Works](#-how-it-works)
- 📊 [Data Sources](#-data-sources)
- 🚀 [Usage Instructions](#-usage-instructions)
- 🎨 [Features](#-features)
- 🛠️ [Technical Stack](#️-technical-stack)
- 🌐 [Redundancy Strategy](#-redundancy-strategy)
- 📱 [Browser Compatibility](#-browser-compatibility)
- 🤝 [Contributing](#-contributing)
- 📄 [License](#-license)
- 🆘 [Support](#-support)

## 🔐 Overview

The Hexbon Decryption Tool is a standalone web application that allows you to decrypt and view your encrypted data from <a href="https://hexbon.com" target="_blank">Hexbon.com</a>. All decryption happens locally in your browser - your encryption keys and data are never sent to any server.

## 🌐 Live Access

This tool is available through multiple redundancy hosting options:

- **Primary**: <a href="https://hexbon.pages.dev" target="_blank">hexbon.pages.dev</a> (Cloudflare Pages)
- **Backup**: <a href="https://ricu23.github.io/hexbon.pages.dev" target="_blank">ricu23.github.io/hexbon.pages.dev</a> (GitHub Pages)
- **Source**: <a href="https://github.com/Ricu23/hexbon.pages.dev" target="_blank">GitHub Repository</a>
- **Local Development**: [See setup instructions](#-local-development) for running locally

## 🔒 Privacy & Security

### What We Don't Store
- ❌ Your encryption keys
- ❌ Your decrypted data
- ❌ Your search queries
- ❌ Your usage patterns

### What Happens Locally
- ✅ All decryption in your browser
- ✅ Local storage for preferences only
- ✅ No network requests for decryption
- ✅ Complete data isolation

### Zero Analytics Policy

This tool contains **absolutely no tracking, analytics, or data collection scripts**. We do not use:
- ❌ Google Analytics
- ❌ Microsoft Clarity or Application Insights
- ❌ Facebook Pixel
- ❌ Hotjar or other heatmap tools
- ❌ Mixpanel, Amplitude, or similar analytics
- ❌ Error tracking services (Sentry, Bugsnag, etc.)
- ❌ CDN analytics or tracking pixels
- ❌ Social media tracking widgets
- ❌ Any third-party scripts that could access your data

**Privacy Guarantee**: The only external resources loaded are Tailwind CSS (for styling) and fonts. No JavaScript analytics libraries or tracking mechanisms are present.

## 🏠 Local Development

### Simple Local Setup

Running this project locally is incredibly simple - no build tools, dependencies, or complex setup required:

1. **Download Files**: Get `index.html` and `script.js` from this repository
2. **Same Folder**: Place both files in the same directory
3. **Open**: Double-click `index.html` or open it in any web browser
4. **That's It**: The tool is now running locally on your machine

#### Option 1: Clone with Git

```bash
git clone https://github.com/Ricu23/hexbon.pages.dev.git
cd hexbon.pages.dev
# Then open index.html in your browser
```

#### Option 2: Download ZIP

**<a href="https://github.com/Ricu23/hexbon.pages.dev/archive/refs/heads/main.zip" target="_blank">📥 Download ZIP</a>**

```bash
# Extract the ZIP file and open index.html in your browser
```

#### Option 3: Manual Download

```bash
mkdir hexbon-local
cd hexbon-local
# Download index.html and script.js individually from the repository
# Then open index.html in your browser
```

**Benefits of Local Setup**:
- ✅ Complete offline operation
- ✅ No internet dependency after initial download
- ✅ Full control over your environment
- ✅ No hosting service dependencies
- ✅ Enhanced privacy and security

## 🛡️ Security Features

- **Client-Side Decryption**: All cryptographic operations happen in your browser
- **No Server Communication**: Your keys and data never leave your device
- **AES-GCM Encryption**: Industry-standard 256-bit encryption
- **PBKDF2 Key Derivation**: 150,000 iterations with SHA-256
- **Zero-Knowledge Architecture**: We cannot access your decrypted data

## 🔧 How It Works

### Encryption Specification

The tool uses the following cryptographic parameters:

```javascript
// Encryption Configuration
VERSION: 'v1'
ALGORITHM: 'AES-GCM'
KEY_SIZE: 256 bits
PBKDF2_ITERATIONS: 150,000
PBKDF2_HASH: 'SHA-256'
SALT_BYTES: 16
IV_BYTES: 12
```

### Data Format

Encrypted data follows this format:
```
version:base64_salt:base64_iv:base64_ciphertext
```

**Example:**

**Encrypted Data:**
```
v1:wZIjnDj8KMmOVmTv4koLDg==:kOJAMS74rivuJL9F:+4yCmLjV5D55L/B/y7r9ngTtovL/sHJ2KaAh8cbkK1Gt4D//WnRMN8QnKEXEpLHMBzVDV+m0P7pitBdOInaBksCczlXIaWgIOKFU2/V58A35yyJ3aAnvprDduZiRe0t2RvDx2UPG+8GI0G0muHJe9eBwYTL/O6oMqOB7gA25sBh8IAE1tdvHi6RICfjshkun0arSw4NEEE4wbKg4ZPOybj/gA+SsIPZ3fdlVE56cW8Z4w5bp6dAAMgQa9UnzejSLR0USSZH0bqDe66yDbfug+AMnt9F9GaDrTJkPLpOvMWYAzmi+c9X4pEZ7M2D4mWkmZgXsY3JpqwJdLhPe/1+zByGzChCCzA8xlKo+MJoZvbkdoFxCns+Fj5ECKHtSvkniLixxPFmCfnC8oED/XXGjXme0PxYvCKORthZpp1EDgoJ085Y3coesR7tOMftck+MXFEzy+EFr8kmYPHAnB0poMPo6bLyqw60HePK3gG5dsCzm+zl7pU8m9jHNK2qQa5Yi6yVd3qgmkmxZ4EbH0+BWhLG/o7A1WWvZucWWwVGSc4tRL0TFSHYMt09DTu/qs/MQAHRUD9f9UJF8aHGAEU59LYC6nBwui+sKlII95tiUDEZx1X24wsLMTqQmzhNYKUTFc6QS9lAG/fNv8P7mjnAiRBFj4txTNdkVNNovQcg14uLYiY/0XCn4tF3O3C5SBshXha6GAEg3yLdHQpjJBzmdLQfD7Y85rjuvxm8k8J052RN14ME5VnPqthYkHmB3UmHTsV8JijG/If8UOdquH7ChLjrSSX9VXgBfzpLUdHG0e+upBnMlNxVBwp1d/Pyw/vXSoXw8Z3t3+dCd+xT0BG/vA5Cx3MYoXRzLOeg5PW3yBzh2GqsBwyLvI2y10Xxi/Sqn5qnf34XObCrHsg8K0gYgvYspkpCBOfEGS7E5n1TVq7fnfJKH4ypsglRPkkapAFLi3CB+z4WTXJc/3shwS1PaJg==
```

**Password:**
```
asd
```

*This example demonstrates the complete encrypted data format and the corresponding password needed for decryption. You can use these values to test the tool functionality.*

### Decryption Process

1. **Input Validation**: Verify encrypted data format
2. **Key Derivation**: Combine your encryption key with reference key (RK)
3. **Salt & IV Extraction**: Extract cryptographic parameters from payload
4. **PBKDF2 Key Generation**: Derive AES key using 150,000 iterations
5. **AES-GCM Decryption**: Decrypt and authenticate the data
6. **JSON Parsing**: Parse decrypted data for dashboard display

### Reference Key (RK) Information

The Reference Key (RK) is currently **universal** across all Hexbon accounts. This means:
- All users share the same RK value
- It acts as a secondary cryptographic component
- Your personal encryption key remains unique and private

**Future Considerations**: We are analyzing the benefits of making the RK account-specific. This would provide an additional layer of security by ensuring each user has a unique RK, but we're still evaluating the implementation complexity and user experience implications.

## 📊 Data Sources

You can obtain encrypted data from several sources:

### 1. Hexbon Dashboard Export
- Log into <a href="https://hexbon.com" target="_blank">Hexbon.com</a>
- Navigate to Settings → Export Data
- Download your encrypted JSON backup

### 2. Email Backups
- Automated email backups from Hexbon
- Contains your encrypted data in the email attachment
- Use the same encryption key you use on Hexbon


## 🚀 Usage Instructions

### Step 1: Access the Tool
Visit any of the hosted versions:
- <a href="https://hexbon.pages.dev" target="_blank">hexbon.pages.dev</a>
- <a href="https://ricu23.github.io/hexbon.pages.dev" target="_blank">GitHub Pages Mirror</a>

### Step 2: Enter Your Credentials
1. **Encryption Key**: Your personal encryption password from Hexbon
2. **Encrypted Data**: Paste your encrypted JSON data
3. **Reference Key (RK)**: Pre-filled system key (do not modify)

### Step 3: Decrypt and Browse
- Click "Decrypt Data" to process your information
- Browse your data in the interactive dashboard
- Search through your records and sections
- Copy values to clipboard as needed

## 🎨 Features

### Interactive Dashboard
- **Card-Based Layout**: Visual organization of your data
- **Search Functionality**: Find specific records, sections, or notes
- **Modal View**: Detailed record examination
- **Dark/Light Mode**: Automatic theme detection with manual toggle

### Data Management
- **Read-Only Access**: View and copy data safely
- **Secret Masking**: Passwords and sensitive data are hidden by default
- **Copy to Clipboard**: One-click copying of any value
- **JSON Export**: View raw decrypted JSON data

### User Experience
- **Responsive Design**: Works on desktop, tablet, and mobile
- **Dismissible Banner**: Information about read-only mode
- **Auto-Selection**: First record automatically selected for quick access
- **Persistent Preferences**: Remember your settings across sessions

## ️ Technical Stack

- **Frontend**: Vanilla JavaScript (ES6+)
- **Styling**: Tailwind CSS
- **Cryptography**: Web Crypto API
- **Hosting**: Cloudflare Pages + GitHub Pages
- **Icons**: Heroicons (SVG)

##  Redundancy Strategy

This tool provides multiple layers of redundancy:

### Hosting Redundancy
1. **Cloudflare Pages**: Primary hosting with global CDN
2. **GitHub Pages**: Secondary hosting with Git-based deployment
3. **Open Source**: Full source code available for self-hosting

### Access Methods
1. **Direct Web Access**: Through hosted URLs
2. **Git Clone**: Download and run locally
3. **Offline Mode**: Works without internet after initial load

### Data Recovery
1. **Multiple Export Formats**: JSON, individual records
2. **Email Integration**: Automated backup delivery
3. **Cross-Platform**: Works on any device with a modern browser

## 📱 Browser Compatibility

- ✅ Chrome 60+
- ✅ Firefox 55+
- ✅ Safari 12+
- ✅ Edge 79+
- ✅ Mobile browsers (iOS Safari, Chrome Mobile)

## 🤝 Contributing

This is an open-source project. Contributions are welcome!

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License. See the source code for full license text.

## 🆘 Support

### For Decryption Issues
- Verify your encryption key matches your Hexbon account
- Ensure encrypted data is copied completely
- Check that RK (Reference Key) is not modified

### For Technical Issues
- Check browser console for error messages
- Try a different browser or device
- Clear browser cache and try again

### Contact
- **Main Platform**: <a href="https://hexbon.com" target="_blank">Hexbon.com</a>
- **GitHub Issues**: <a href="https://github.com/Ricu23/hexbon.pages.dev/issues" target="_blank">Report bugs or feature requests</a>

---

**⚠️ Important**: This tool is designed for data recovery and redundancy. For creating, editing, or managing your encrypted data, please use the main Hexbon platform at <a href="https://hexbon.com" target="_blank">hexbon.com</a>.

