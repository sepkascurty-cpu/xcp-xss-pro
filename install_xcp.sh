#!/bin/bash

echo "╔══════════════════════════════════════════════════╗"
echo "║      XSS COMMANDER PRO - INSTALLATION           ║"
echo "╚══════════════════════════════════════════════════╝"

echo ""
echo "[*] Checking Python version..."

# Cek Python 3
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 not found! Installing..."
    sudo apt-get update
    sudo apt-get install -y python3 python3-pip
fi

echo "[✓] Python3 is installed"

# Install dependencies
echo ""
echo "[*] Installing dependencies..."
pip3 install requests beautifulsoup4 colorama fake-useragent lxml

# Buat file executable
echo ""
echo "[*] Making script executable..."
chmod +x xcp.py

# Buat symlink
echo ""
echo "[*] Creating system link..."
sudo ln -sf $(pwd)/xcp.py /usr/local/bin/xcp 2>/dev/null

# Buat payload database
echo ""
echo "[*] Creating payload database..."
cat > payloads.json << 'EOF'
{
    "custom": {
        "custom_payloads": [
            "<script>console.log('XSS_DEBUG')</script>",
            "<img src=x onerror=console.error('XSS')>",
            "<svg onload=console.warn('SVG_XSS')>"
        ]
    }
}
EOF

# Buat konfigurasi
echo ""
echo "[*] Creating configuration..."
cat > xcp_config.json << 'EOF'
{
    "timeout": 10,
    "max_threads": 10,
    "user_agent": "random",
    "output_dir": "./xcp_reports"
}
EOF

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║           INSTALLATION COMPLETE!                ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║  Usage:                                         ║"
echo "║    xcp --interactive    # Interactive mode      ║"
echo "║    xcp -u <URL>         # Quick scan           ║"
echo "║    xcp -f <URL>         # Full scan            ║"
echo "║    python3 xcp.py -i    # Alternative          ║"
echo "║                                                ║"
echo "║  Examples:                                     ║"
echo "║    xcp -u https://test.com/page.php           ║"
echo "║    xcp --auto-exploit https://vuln.site       ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "[!] IMPORTANT: Use only for authorized testing!"
echo "[*] Legal Disclaimer: You are responsible for your actions"
