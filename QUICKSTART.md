# Quick Start Guide

Get Cribl Knowledge Manager running in 5 minutes.

## Prerequisites

- Python 3.8 or higher
- A Cribl Cloud account
- API credentials (Client ID and Secret)

## Step 1: Clone and Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/cribl-knowledge-manager.git
cd cribl-knowledge-manager

# Create a virtual environment (recommended)
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate      # macOS/Linux
# or
venv\Scripts\activate         # Windows

# Install dependencies
pip install -r requirements.txt
```

## Step 2: Get Your Cribl Cloud Credentials

### Create API Credentials

1. Log in to [https://cloud.cribl.io](https://cloud.cribl.io)
2. Click your organization name in the top-left
3. Select **Organization Settings**
4. Click **API Credentials** in the left sidebar
5. Click **Create API Credential**
6. Give it a name (e.g., "Knowledge Manager")
7. **Copy the Client ID and Client Secret immediately** - the secret is only shown once!

### Find Your Organization ID

Look at your browser URL when logged into Cribl Cloud:

```
https://main-amazing-varahamihira.cribl.cloud
       └────────────────────────────┘
       This is your Organization ID
```

**Important:** Include the workspace prefix! It's usually `main-` followed by your organization name.

Accepted formats:
- `main-your-org-name`
- `main-your-org-name.cribl.cloud`
- `https://main-your-org-name.cribl.cloud/`

## Step 3: Configure Credentials

### Option A: Config File (Recommended)

```bash
# Copy the template
cp config.ini.template config.ini

# Edit with your favorite editor
nano config.ini   # or vim, code, etc.
```

Fill in your values:

```ini
[cribl]
client_id = QtiEGHZ6Q8QwW6ncfbj3WL8ccurIPtYi
client_secret = YZlYF91LhcgNQ1bZBNWUn4_aDVkezepe5DYxZVE3XGabRfkd4nfgn8IINs3SupwI
organization_id = main-amazing-varahamihira
```

### Option B: Environment Variables

```bash
export CRIBL_CLIENT_ID="your_client_id"
export CRIBL_CLIENT_SECRET="your_client_secret"
export CRIBL_ORG_ID="main-your-org-name"
```

## Step 4: Run the Application

```bash
python app.py
```

The app will:
1. Check dependencies (auto-install if missing)
2. Start on `http://localhost:42001`
3. Open your browser automatically

## Using the Application

### Lookups Tab

1. Select **Source** product (Stream, Edge, or Search) and Worker Group
2. Click **Scan Packs** to discover lookups inside installed Packs
3. Select **Destination** product and Worker Group(s)
4. Choose lookup files to transfer
5. Optionally select **Memory** or **Disk** lookup type per file
6. Click **Transfer** to copy lookups to the destination
7. Click **Commit & Deploy** when ready to apply changes

### Knowledge Tab

1. Select a **Knowledge Type** (Parsers, Variables, Schemas, etc.)
2. Choose **Source** product and Worker Group
3. Select items from the list
4. Optionally click the **Edit** icon to modify before transfer
5. Select **Destination** product and target Worker Group(s)
6. Enter a **Commit Message**
7. Click **Transfer** then **Commit & Deploy**

### Migration Tab

Migrate entire configurations between Cribl Cloud organizations:

1. **Connect** - Enter source and destination organization credentials
   - Client ID, Client Secret, and Organization ID for each
   - Toggle SSL Verification if needed
   - Click **Connect** to validate credentials
2. **Select** - Choose what to migrate:
   - Packs, Lookups, Pipelines, Routes
   - Inputs, Outputs, Global Variables
   - Notifications, Mappings, Knowledge objects
3. **Review** - Preview items that will be migrated
4. **Migrate** - Execute the migration
   - Enable **Dry Run** to simulate without making changes
   - Watch real-time progress with item-by-item status
5. **Done** - Review results and check for any errors

### Marketplace Tab

Browse and install Cribl Packs:

1. Browse the **Pack Catalog** from Cribl's official feed
2. Use **Search** to filter by name, description, or author
3. Click a pack to view details, versions, and compatibility
4. Click **Install** to download and deploy to your environment
5. Select the target **Worker Group** or **Fleet**

### Key Features

- **Pack Lookups**: Click "Scan Packs" to discover lookups embedded in Packs
- **Cribl Badge**: Items with a purple "Cribl" badge are built-in library objects
- **Edit Before Transfer**: Click the edit icon to rename objects or modify content
- **Table Editor**: For CSV lookups, use the smart table editor with auto-sizing columns
- **Multi-Destination**: Select multiple Worker Groups/Fleets to transfer to all at once
- **Pending Deployments**: Transfers are staged - commit and deploy when ready

### Bottom Panels

- **Console**: Shows real-time API activity and any errors
- **curl Commands**: Shows the equivalent HTTP requests for API debugging

## Troubleshooting

### "401 Unauthorized" Error
- Check your Client ID and Secret are correct
- Ensure your API credential hasn't expired

### "404 Not Found" Error
- Verify your Organization ID includes the workspace prefix (e.g., `main-`)
- Check the Worker Group or Fleet name is correct

### "Connection Refused" Error
- Make sure port 42001 is available
- Check no firewall is blocking localhost connections

### Application Won't Start
- Ensure Python 3.8+ is installed: `python3 --version`
- Try reinstalling dependencies: `pip install -r requirements.txt`

### Pack Lookups Not Found
- Click "Scan Packs" button to discover pack lookups
- Pack lookups are shown with pack name prefix (e.g., `HelloPacks.lookup.csv`)

## Next Steps

- Read the full [README.md](README.md) for more details
- Check the console output for debugging information
- Use the curl Commands panel to understand the API calls being made
