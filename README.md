# Cribl Knowledge Manager

A web-based tool for managing and transferring knowledge objects across Cribl Cloud environments (Stream, Search, and Edge).

**Version: 5.0.0** | December 2025

> **Note:** This tool supports **Cribl Cloud only**. On-premises Cribl deployments are not supported.

## Features

### Full Organization Migration
- **Org-to-Org Migration** - Migrate entire configurations between Cribl Cloud organizations
- **Selective Migration** - Choose specific config types: Packs, Lookups, Pipelines, Routes, Inputs, Outputs, Global Variables, Notifications, Mappings, and all Knowledge objects
- **Simulation Mode** - Preview migration with "Dry Run" before making changes
- **Step-by-Step Wizard** - Guided workflow: Connect → Select → Review → Migrate → Done
- **Real-time Progress** - Item-by-item status tracking with success/error indicators
- **SSL Verification Toggle** - Configure SSL verification per environment

### Knowledge Object Management
- **Transfer Knowledge Objects** between Worker Groups, Fleets, and Search
- **Cross-Product Support** - Transfer between Stream, Edge, and Search
- **Multi-Destination Transfer** - Send to multiple Worker Groups/Fleets at once
- **Pack Lookup Scanning** - Automatically discover and extract lookups from installed Packs

### Pack Marketplace
- **Browse Packs** - Explore available Cribl Packs from the official feed
- **Search & Filter** - Find packs by name, description, or author
- **Pack Details** - View descriptions, versions, and compatibility info
- **Quick Install** - Download and install packs directly to your environments

### Supported Object Types
- **Lookups** (CSV files) - Memory or Disk-based
- **Event Breakers** - Rulesets for parsing raw data
- **Parsers** - Field extraction configurations
- **Variables / Macros** - Reusable values and expressions
- **Regexes** - Regular expression patterns
- **Grok Patterns** - Named regex patterns for parsing
- **Schemas** - Field definitions and mappings
- **Parquet Schemas** - Column definitions for Parquet files
- **Database Connections** - External database configurations
- **HMAC Functions** - Hash-based message authentication
- **AppScope Configs** - Application instrumentation settings
- **Guard Rules (SDS)** - Sensitive data scrubbing rules

### Editing & Workflow
- **Edit Before Transfer** - Modify objects, rename IDs, and change libraries before deploying
- **Built-in JSON Editor** - Syntax highlighting for knowledge objects
- **Table Editor** - Smart CSV editing with:
  - Auto-sizing columns based on content
  - Word wrap toggle for long content
  - Resizable column handles
  - Tables fill panel width
- **Bulk Operations** - Select and transfer multiple objects at once
- **Pending Deployments** - Stage changes, then commit and deploy together
- **Persistent State** - Pending deployments saved to browser localStorage

### Developer Tools
- **Console Panel** - Real-time API activity logging
- **curl Commands Panel** - View equivalent HTTP requests for all operations
- **Activity Logging** - Track all operations with timestamps

## Requirements

- Python 3.8+
- Cribl Cloud account with API credentials

## Quick Start

See [QUICKSTART.md](QUICKSTART.md) for detailed setup instructions.

```bash
# Clone the repository
git clone https://github.com/criblio/cribl-knowledge-manager.git
cd cribl-knowledge-manager

# Setup virtual environment
python3 -m venv venv
source venv/bin/activate  # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Configure credentials
cp config.ini.template config.ini
# Edit config.ini with your Cribl Cloud credentials

# Run
python app.py
```

The application will start on `http://localhost:42001` and auto-open in your browser.

## Configuration

### Option 1: Config File (Recommended)

Copy `config.ini.template` to `config.ini` and fill in your credentials:

```ini
[cribl]
client_id = your_client_id_here
client_secret = your_client_secret_here
organization_id = main-your-org-name
```

### Option 2: Environment Variables (More Secure)

```bash
export CRIBL_CLIENT_ID="your_client_id"
export CRIBL_CLIENT_SECRET="your_client_secret"
export CRIBL_ORG_ID="main-your-org-name"
```

> **Security Note:** Environment variables are preferred as they don't persist secrets to disk. If using `config.ini`, ensure it's never committed to version control.

### Getting API Credentials

1. Log in to [Cribl Cloud](https://cloud.cribl.io)
2. Click your organization name → **Organization Settings**
3. Navigate to **API Credentials** in the left sidebar
4. Click **Create API Credential**
5. Copy the Client ID and Client Secret (shown only once!)

### Finding Your Organization ID

Your Organization ID is in the browser URL when logged into Cribl Cloud:

```
https://main-your-org-name.cribl.cloud
       └──────────────────┘
       This is your Organization ID
```

⚠️ **Important:** Include the workspace prefix (usually `main-`)!

Accepted formats:
- `main-your-org-name`
- `main-your-org-name.cribl.cloud`
- `https://main-your-org-name.cribl.cloud/`

## Architecture

- **Backend:** Flask server (`app.py`) - handles OAuth authentication and proxies Cribl Cloud API calls
- **Frontend:** Single-file React SPA (`index.html`) - no build step required

## Related Tools

### migrate_configs.py (Professional Services Script)

The repository also includes `migrate_configs.py`, a comprehensive configuration migration script from Cribl Professional Services. This script handles full configuration migration including:

- Routes, Pipelines, Inputs, Outputs
- Packs (full pack migration)
- Notifications & Notification Targets
- Mappings & Fleet Mappings
- All knowledge objects

**Use Cases:**
- On-premises to Cribl Cloud migration
- Full environment cloning
- Bulk configuration backup/restore

See `conf.json` for configuration options. Requires the `cribl_python_api_wrapper` package.

## License

MIT License - see [LICENSE](LICENSE) for details.
