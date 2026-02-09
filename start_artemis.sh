#!/bin/bash
#
# Start Artemis Threat Hunting Platform
#

cd "$(dirname "$0")"

echo "======================================================================"
echo "  🏹 Starting Artemis Threat Hunting Platform"
echo "======================================================================"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Run setup first:"
    echo "   python3 -m venv venv"
    echo "   source venv/bin/activate"
    echo "   pip install -r requirements.txt"
    exit 1
fi

# Check Splunk credentials
if [ -z "$SPLUNK_TOKEN" ] && [ -z "$SPLUNK_USERNAME" ]; then
    echo "⚠️  Warning: Splunk credentials not set!"
    echo "   Set SPLUNK_TOKEN or SPLUNK_USERNAME/SPLUNK_PASSWORD"
    echo ""
    echo "   Example:"
    echo "   export SPLUNK_TOKEN=\"your-token-here\""
    echo ""
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Activate virtual environment
source venv/bin/activate

# Install/upgrade dependencies
echo ""
echo "📦 Checking dependencies..."
pip install -q --upgrade -r requirements.txt

echo ""
echo "🚀 Launching Artemis Server..."
echo ""
echo "   Web UI:     http://localhost:8000"
echo "   API Docs:   http://localhost:8000/docs"
echo ""
echo "======================================================================"
echo ""

# Start server
python artemis_server.py
