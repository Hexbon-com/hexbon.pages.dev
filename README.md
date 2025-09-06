# Hexbon Decryption Tool

A secure, client-side decryption tool for accessing your Hexbon encrypted data. This tool serves as a redundancy solution to ensure you always have access to your encrypted information, even if the main Hexbon service is unavailable.

## 🔐 Overview

The Hexbon Decryption Tool is a standalone web application that allows you to decrypt and view your encrypted data from [Hexbon.com](https://hexbon.com). All decryption happens locally in your browser - your encryption keys and data are never sent to any server.

## 🌐 Live Access

This tool is available through multiple redundancy hosting options:

- **Primary**: [hexbon.pages.dev](https://hexbon.pages.dev) (Cloudflare Pages)
- **Backup**: [ricu23.github.io/hexbon.pages.dev](https://ricu23.github.io/hexbon.pages.dev) (GitHub Pages)
- **Source**: [GitHub Repository](https://github.com/Ricu23/hexbon.pages.dev)

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
```
v1:kX9mY2L8vB3nA5s7dQ1wPg==:8HjL9kN3mF2sA1wQ:9sK3mP8vN7lQ2...
```

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
- Log into [Hexbon.com](https://hexbon.com)
- Navigate to Settings → Export Data
- Download your encrypted JSON backup

### 2. Email Backups
- Automated email backups from Hexbon
- Contains your encrypted data in the email attachment
- Use the same encryption key you use on Hexbon

### 3. Manual Backups
- Any previously saved encrypted exports
- Shared encrypted data from team members

## 🚀 Usage Instructions

### Step 1: Access the Tool
Visit any of the hosted versions:
- [hexbon.pages.dev](https://hexbon.pages.dev)
- [GitHub Pages Mirror](https://ricu23.github.io/hexbon.pages.dev)

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

## 🛠️ Technical Stack

- **Frontend**: Vanilla JavaScript (ES6+)
- **Styling**: Tailwind CSS
- **Cryptography**: Web Crypto API
- **Hosting**: Cloudflare Pages + GitHub Pages
- **Icons**: Heroicons (SVG)

## 🏠 Local Development

### Simple Local Setup

Running this project locally is incredibly simple - no build tools, dependencies, or complex setup required:

1. **Download Files**: Get `index.html` and `script.js` from this repository
2. **Same Folder**: Place both files in the same directory
3. **Open**: Double-click `index.html` or open it in any web browser
4. **That's It**: The tool is now running locally on your machine

```bash
# Option 1: Clone with Git
git clone https://github.com/Ricu23/hexbon.pages.dev.git
cd hexbon.pages.dev
# Then open index.html in your browser

# Option 2: Download ZIP
# Visit: https://github.com/Ricu23/hexbon.pages.dev/archive/refs/heads/main.zip
# Extract the ZIP file
# Open index.html in your browser

# Option 3: Manual download
mkdir hexbon-local
cd hexbon-local
# Download index.html and script.js individually
# Then open index.html in your browser
```

**Benefits of Local Setup**:
- ✅ Complete offline operation
- ✅ No internet dependency after initial download
- ✅ Full control over your environment
- ✅ No hosting service dependencies
- ✅ Enhanced privacy and security

## 🌐 Redundancy Strategy

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
- **Main Platform**: [Hexbon.com](https://hexbon.com)
- **GitHub Issues**: [Report bugs or feature requests](https://github.com/Ricu23/hexbon.pages.dev/issues)

---

**⚠️ Important**: This tool is designed for data recovery and redundancy. For creating, editing, or managing your encrypted data, please use the main Hexbon platform at [hexbon.com](https://hexbon.com).

**🔐 Security Notice**: Always verify you're using the official hosted versions. Never enter your encryption key on suspicious or unofficial sites.
