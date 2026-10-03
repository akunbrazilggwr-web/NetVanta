# NetVanta 1.0.1

Vercel-ready static frontend + Node.js Function API.

## Deploy to Vercel

### Vercel Drop
1. Upload this ZIP/folder at Vercel Drop.
2. Vercel detects the static site and the `api/scan.js` Node.js Function.
3. Deploy with the default settings. Do not set a custom build command or output directory.

### GitHub
1. Put the contents of this folder at the repository root.
2. Import the repository into Vercel.
3. Framework Preset: Other (or leave auto-detected).
4. Build Command: leave empty.
5. Output Directory: leave empty.
6. Deploy.

The site must have `index.html` at the project root and `api/scan.js` under `/api`.

## Important limitations

The web version can perform DNS/HTTP checks and limited TCP connectivity checks from the Vercel server. It cannot access the user's Wi-Fi adapter, LAN interface, or capture packets like Wireshark. The WiFi feature therefore reports TCP/IP exposure only; it does not brute-force Wi-Fi credentials.

Use the scanner only on systems you own or are authorized to test.
