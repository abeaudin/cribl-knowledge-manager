#!/usr/bin/env node
/**
 * Cribl Knowledge Manager - Backend Server (Node.js)
 * Version: 5.0.0
 * Date: December 2025
 *
 * This Express application serves as a backend proxy for the Cribl Cloud API,
 * enabling users to manage Knowledge items across Cribl Cloud deployments
 * (Stream, Edge, and Search).
 */

// =============================================================================
// CONFIGURATION
// =============================================================================

const DEBUG_MODE = false;
const COMMIT_PREFIX = "[KnowledgeManager]";
const PORT = 42001;

// =============================================================================
// IMPORTS
// =============================================================================

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { execSync } = require('child_process');
const ini = require('ini');
const cron = require('node-cron');
const archiver = require('archiver');
const AdmZip = require('adm-zip');

// SQLite with better-sqlite3 (synchronous, faster)
let Database;
try {
    Database = require('better-sqlite3');
} catch (e) {
    console.error('[ERROR] better-sqlite3 not installed. Run: npm install');
    process.exit(1);
}

// =============================================================================
// LOGGING UTILITIES
// =============================================================================

function debugLog(message) {
    if (DEBUG_MODE) {
        console.log(message);
    }
}

function sanitizeUrlForLogging(url) {
    if (!url) return url;
    return url
        .replace(/([?&]token=)[^&]+/g, '$1***')
        .replace(/(Bearer\s+)[a-zA-Z0-9\-_\.]+/g, '$1***');
}

// =============================================================================
// EXPRESS APPLICATION SETUP
// =============================================================================

const app = express();

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// CORS configuration - localhost only
app.use(cors({
    origin: [
        'http://localhost:42001',
        'http://127.0.0.1:42001',
        /^http:\/\/localhost:\d+$/,
        /^http:\/\/127\.0\.0\.1:\d+$/
    ],
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Static files
app.use('/static', express.static(path.join(__dirname, 'static')));

// Security headers
app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Content-Security-Policy',
        "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com https://cdnjs.cloudflare.com https://fonts.googleapis.com; " +
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; " +
        "img-src 'self' data:; " +
        "connect-src 'self' http://localhost:* http://127.0.0.1:* https://*.cribl.cloud https://unpkg.com;"
    );
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
});

// =============================================================================
// INPUT VALIDATION
// =============================================================================

function validateFilename(filename) {
    if (!filename) {
        throw new Error('Filename cannot be empty');
    }
    if (filename.includes('..') || filename.includes('/') || filename.includes('\\') || filename.includes('\0')) {
        throw new Error('Invalid filename: path traversal detected');
    }
    if (!/^[a-zA-Z0-9_\-\.]+$/.test(filename)) {
        throw new Error('Invalid filename: only alphanumeric, underscore, hyphen, and period allowed');
    }
    if (filename.length > 255) {
        throw new Error('Filename too long (max 255 characters)');
    }
    return filename;
}

function validateWorkerGroup(groupName) {
    if (!groupName) {
        throw new Error('Worker group name cannot be empty');
    }
    if (groupName.includes('..') || groupName.includes('/') || groupName.includes('\\') || groupName.includes('\0')) {
        throw new Error('Invalid worker group name');
    }
    if (!/^[a-zA-Z0-9_\-\.]+$/.test(groupName)) {
        throw new Error('Invalid worker group name: only alphanumeric, underscore, hyphen allowed');
    }
    if (groupName.length > 100) {
        throw new Error('Worker group name too long (max 100 characters)');
    }
    return groupName;
}

function validateApiType(apiType) {
    const allowedTypes = ['stream', 'search', 'edge'];
    if (!allowedTypes.includes(apiType)) {
        throw new Error(`Invalid API type: must be one of ${allowedTypes.join(', ')}`);
    }
    return apiType;
}

// =============================================================================
// GLOBAL APPLICATION STATE
// =============================================================================

const appConfig = {
    authenticated: false,
    token: null,
    tokenExpiry: null,
    clientId: null,
    clientSecret: null,
    organizationId: null,
    baseUrl: null,
    isDirectTenant: false
};

// =============================================================================
// DATABASE PATHS
// =============================================================================

const MARKETPLACE_DB_PATH = path.join(__dirname, 'marketplace.db');
const MIGRATION_HISTORY_DB_PATH = path.join(__dirname, 'migration_history.db');
const SNAPSHOTS_DB_PATH = path.join(__dirname, 'snapshots.db');

// =============================================================================
// FEED PROVIDERS CONFIGURATION
// =============================================================================

const FEED_PROVIDERS = {
    // FREE - No API Key Required
    'spamhaus_drop': {
        name: 'Spamhaus DROP',
        description: 'Dont Route Or Peer - list of netblocks to drop',
        url: 'https://www.spamhaus.org/drop/drop.txt',
        authType: 'none',
        format: 'spamhaus_txt',
        category: 'ip_blocklist',
        defaultFilename: 'spamhaus_drop.csv',
        updateFrequency: 'daily'
    },
    'feodo_tracker': {
        name: 'Feodo Tracker',
        description: 'Botnet C2 IP blocklist from abuse.ch',
        url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',
        authType: 'none',
        format: 'csv',
        category: 'botnet_c2',
        defaultFilename: 'feodo_tracker.csv',
        updateFrequency: 'hourly'
    },
    'urlhaus': {
        name: 'URLhaus',
        description: 'Malware URLs from abuse.ch',
        url: 'https://urlhaus.abuse.ch/downloads/csv_recent/',
        authType: 'none',
        format: 'csv',
        category: 'malware_urls',
        defaultFilename: 'urlhaus.csv',
        updateFrequency: 'hourly'
    },
    'tor_exit_nodes': {
        name: 'Tor Exit Nodes (Official)',
        description: 'Official Tor Project exit node list',
        url: 'https://check.torproject.org/torbulkexitlist',
        authType: 'none',
        format: 'txt_lines',
        category: 'anonymizer',
        defaultFilename: 'tor_exit_nodes.csv',
        updateFrequency: 'hourly'
    },
    'blocklist_de': {
        name: 'Blocklist.de All Attacks',
        description: 'IPs that attacked services in the last 48 hours',
        url: 'https://lists.blocklist.de/lists/all.txt',
        authType: 'none',
        format: 'txt_lines',
        category: 'ip_blocklist',
        defaultFilename: 'blocklist_de.csv',
        updateFrequency: 'daily'
    },
    'firehol_level1': {
        name: 'FireHOL Level 1',
        description: 'Basic IP blocklist with minimal false positives',
        url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
        authType: 'none',
        format: 'txt_lines',
        category: 'ip_blocklist',
        defaultFilename: 'firehol_level1.csv',
        updateFrequency: 'daily'
    },
    'openphish': {
        name: 'OpenPhish Community',
        description: 'Phishing URLs (community feed)',
        url: 'https://openphish.com/feed.txt',
        authType: 'none',
        format: 'txt_lines',
        category: 'phishing',
        defaultFilename: 'openphish.csv',
        updateFrequency: 'hourly'
    },
    'majestic_million': {
        name: 'Majestic Million',
        description: 'Top 1 million domains ranked by referring subnets',
        url: 'https://downloads.majestic.com/majestic_million.csv',
        authType: 'none',
        format: 'csv',
        category: 'domain_ranking',
        defaultFilename: 'majestic_million.csv',
        updateFrequency: 'daily'
    }
    // Additional providers can be added here...
};

// Default feeds configuration
const DEFAULT_FEEDS = [
    { providerId: 'spamhaus_drop', name: 'Spamhaus DROP', lookupFilename: 'spamhaus_drop.csv', scheduleCron: '0 2 * * *', enabled: false, autoDeploy: false },
    { providerId: 'blocklist_de', name: 'Blocklist.de All Attacks', lookupFilename: 'blocklist_de.csv', scheduleCron: '0 3 * * *', enabled: false, autoDeploy: false },
    { providerId: 'firehol_level1', name: 'FireHOL Level 1', lookupFilename: 'firehol_level1.csv', scheduleCron: '0 4 * * *', enabled: false, autoDeploy: false },
    { providerId: 'feodo_tracker', name: 'Feodo Tracker', lookupFilename: 'feodo_tracker.csv', scheduleCron: '0 */4 * * *', enabled: false, autoDeploy: false },
    { providerId: 'tor_exit_nodes', name: 'Tor Exit Nodes (Official)', lookupFilename: 'tor_exit_nodes.csv', scheduleCron: '0 */4 * * *', enabled: false, autoDeploy: false },
    { providerId: 'openphish', name: 'OpenPhish Community', lookupFilename: 'openphish.csv', scheduleCron: '0 */6 * * *', enabled: false, autoDeploy: false },
    { providerId: 'majestic_million', name: 'Majestic Million', lookupFilename: 'majestic_million.csv', scheduleCron: '0 1 * * *', enabled: false, autoDeploy: false }
];

// =============================================================================
// DATABASE INITIALIZATION
// =============================================================================

function initMarketplaceDb() {
    const db = new Database(MARKETPLACE_DB_PATH);

    db.exec(`
        CREATE TABLE IF NOT EXISTS feeds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider_id TEXT NOT NULL,
            name TEXT NOT NULL,
            enabled INTEGER DEFAULT 0,
            lookup_filename TEXT NOT NULL,
            schedule_cron TEXT DEFAULT '0 6 * * *',
            targets TEXT DEFAULT '{}',
            auto_deploy INTEGER DEFAULT 0,
            commit_message TEXT,
            auth_config TEXT,
            last_sync TEXT,
            last_sync_status TEXT,
            last_sync_message TEXT,
            content_hash TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.exec(`
        CREATE TABLE IF NOT EXISTS sync_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            feed_id INTEGER NOT NULL,
            sync_time TEXT DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL,
            message TEXT,
            records_count INTEGER,
            content_hash TEXT,
            preview_data TEXT,
            FOREIGN KEY (feed_id) REFERENCES feeds(id)
        )
    `);

    // Insert default feeds if empty
    const count = db.prepare('SELECT COUNT(*) as cnt FROM feeds').get();
    if (count.cnt === 0) {
        const insert = db.prepare(`
            INSERT INTO feeds (provider_id, name, lookup_filename, schedule_cron, enabled, auto_deploy, targets)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `);

        for (const feed of DEFAULT_FEEDS) {
            insert.run(
                feed.providerId,
                feed.name,
                feed.lookupFilename,
                feed.scheduleCron,
                feed.enabled ? 1 : 0,
                feed.autoDeploy ? 1 : 0,
                '{}'
            );
        }
        debugLog(`[MARKETPLACE] Inserted ${DEFAULT_FEEDS.length} default feeds`);
    }

    db.close();
    debugLog('[MARKETPLACE] Database initialized');
}

function initMigrationHistoryDb() {
    const db = new Database(MIGRATION_HISTORY_DB_PATH);

    db.exec(`
        CREATE TABLE IF NOT EXISTS migrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_org TEXT NOT NULL,
            dest_org TEXT NOT NULL,
            dest_client_id TEXT,
            dest_client_secret_hash TEXT,
            simulate_only INTEGER DEFAULT 0,
            success_count INTEGER DEFAULT 0,
            fail_count INTEGER DEFAULT 0,
            status TEXT DEFAULT 'completed',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.exec(`
        CREATE TABLE IF NOT EXISTS migration_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            migration_id INTEGER NOT NULL,
            item_id TEXT NOT NULL,
            item_type TEXT NOT NULL,
            item_type_path TEXT NOT NULL,
            product TEXT NOT NULL,
            source_group TEXT NOT NULL,
            dest_group TEXT NOT NULL,
            status TEXT DEFAULT 'migrated',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (migration_id) REFERENCES migrations(id)
        )
    `);

    db.close();
    debugLog('[MIGRATION_HISTORY] Database initialized');
}

function initSnapshotsDb() {
    const db = new Database(SNAPSHOTS_DB_PATH);

    db.exec(`
        CREATE TABLE IF NOT EXISTS snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            source_org_id TEXT NOT NULL,
            source_org_name TEXT,
            worker_group TEXT,
            product TEXT DEFAULT 'stream',
            product_version TEXT,
            config_count INTEGER DEFAULT 0,
            size_bytes INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.exec(`
        CREATE TABLE IF NOT EXISTS snapshot_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id INTEGER NOT NULL,
            config_type TEXT NOT NULL,
            config_data TEXT NOT NULL,
            item_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
        )
    `);

    db.close();
    debugLog('[SNAPSHOTS] Database initialized');
}

function getDbConnection(dbPath = MARKETPLACE_DB_PATH) {
    return new Database(dbPath);
}

// =============================================================================
// CONFIG FILE LOADING
// =============================================================================

function loadConfigFile() {
    // Try environment variables first
    const envConfig = {
        clientId: process.env.CRIBL_CLIENT_ID,
        clientSecret: process.env.CRIBL_CLIENT_SECRET,
        organizationId: process.env.CRIBL_ORG_ID
    };

    if (envConfig.clientId && envConfig.clientSecret && envConfig.organizationId) {
        return [envConfig, 'environment'];
    }

    // Try config.ini file
    const configPath = path.join(__dirname, 'config.ini');
    if (fs.existsSync(configPath)) {
        try {
            const config = ini.parse(fs.readFileSync(configPath, 'utf-8'));
            if (config.cribl) {
                return [{
                    clientId: config.cribl.client_id,
                    clientSecret: config.cribl.client_secret,
                    organizationId: config.cribl.organization_id
                }, 'config.ini'];
            }
        } catch (e) {
            debugLog(`[ERROR] Failed to parse config.ini: ${e.message}`);
        }
    }

    return [null, null];
}

// =============================================================================
// AUTHENTICATION HELPERS
// =============================================================================

async function getBearerToken(clientId, clientSecret) {
    const tokenUrl = 'https://login.cribl.cloud/oauth/token';
    const response = await fetch(tokenUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            grant_type: 'client_credentials',
            client_id: clientId,
            client_secret: clientSecret,
            audience: 'https://api.cribl.cloud'
        })
    });

    if (!response.ok) {
        const error = await response.text();
        throw new Error(`Authentication failed: ${error}`);
    }

    const data = await response.json();
    return data.access_token;
}

function extractOrgIdAndBaseUrl(organizationId) {
    if (!organizationId) {
        return [null, null, false];
    }

    let orgId = organizationId;
    let baseUrl = null;
    let isDirectTenant = false;

    // Handle full URLs
    if (organizationId.includes('://')) {
        try {
            const url = new URL(organizationId);
            baseUrl = `${url.protocol}//${url.host}`;
            const hostParts = url.host.split('.');
            if (hostParts.length >= 3 && url.host.endsWith('.cribl.cloud')) {
                orgId = hostParts.slice(0, -2).join('.');
            }
            isDirectTenant = true;
        } catch (e) {
            // Not a valid URL, treat as org ID
        }
    }

    // Handle tenant subdomain format
    if (!baseUrl && organizationId.includes('.cribl.cloud')) {
        baseUrl = `https://${organizationId}`;
        const parts = organizationId.replace('.cribl.cloud', '').split('.');
        orgId = parts.join('.');
        isDirectTenant = true;
    }

    // Standard org ID format
    if (!baseUrl) {
        baseUrl = `https://${orgId}.cribl.cloud`;
    }

    return [orgId, baseUrl, isDirectTenant];
}

function getBaseUrl() {
    if (appConfig.baseUrl) {
        return appConfig.baseUrl;
    }
    const orgId = appConfig.organizationId;
    if (!orgId) return null;

    if (orgId.endsWith('.cribl.cloud')) {
        return `https://${orgId}`;
    }
    return `https://${orgId}.cribl.cloud`;
}

function buildApiUrl(apiType, workerGroup = null, urlPath = '', query = '') {
    const baseUrl = getBaseUrl();
    let basePath = `${baseUrl}/api/v1`;

    if (workerGroup) {
        basePath += `/m/${workerGroup}`;
    }

    let url = basePath + urlPath;
    if (query) {
        url += `?${query}`;
    }

    return url;
}

// =============================================================================
// API ROUTES - Static Files
// =============================================================================

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/cribl-logo.svg', (req, res) => {
    res.sendFile(path.join(__dirname, 'cribl-logo.svg'));
});

// =============================================================================
// API ROUTES - Authentication
// =============================================================================

app.post('/api/auth/login', async (req, res) => {
    let { client_id: clientId, client_secret: clientSecret, organization_id: organizationId } = req.body;

    // Try config file if credentials not provided
    if (!clientId || !clientSecret) {
        const [config] = loadConfigFile();
        if (config) {
            clientId = config.clientId;
            clientSecret = config.clientSecret;
            organizationId = organizationId || config.organizationId;
        }
    }

    const [orgId, baseUrl, isDirectTenant] = extractOrgIdAndBaseUrl(organizationId);

    debugLog(`\n[DEBUG] Login attempt:`);
    debugLog(`   Input: ${organizationId}`);
    debugLog(`   Extracted: Org ID: ${orgId}`);
    debugLog(`   Base URL: ${baseUrl}`);
    debugLog(`   Direct Tenant: ${isDirectTenant}`);

    if (!clientId || !clientSecret || !orgId) {
        return res.status(400).json({ error: 'Missing credentials' });
    }

    try {
        const token = await getBearerToken(clientId, clientSecret);
        appConfig.authenticated = true;
        appConfig.token = token;
        appConfig.clientId = clientId;
        appConfig.clientSecret = clientSecret;
        appConfig.organizationId = orgId;
        appConfig.baseUrl = baseUrl;
        appConfig.isDirectTenant = isDirectTenant;

        debugLog(`   [OK] Authentication successful!`);

        res.json({
            success: true,
            organization_id: orgId,
            base_url: baseUrl,
            is_direct_tenant: isDirectTenant
        });
    } catch (e) {
        debugLog(`   [ERROR] Authentication failed: ${e.message}`);
        res.status(401).json({ error: e.message });
    }
});

app.post('/api/logout', (req, res) => {
    appConfig.authenticated = false;
    appConfig.token = null;
    appConfig.clientId = null;
    appConfig.clientSecret = null;
    appConfig.organizationId = null;
    appConfig.baseUrl = null;
    appConfig.isDirectTenant = false;

    debugLog('[INFO] User logged out - session cleared');
    res.json({ success: true, message: 'Logged out successfully' });
});

app.get('/api/auth/status', (req, res) => {
    res.json({
        authenticated: appConfig.authenticated,
        organization_id: appConfig.organizationId
    });
});

// =============================================================================
// API ROUTES - Configuration
// =============================================================================

app.get('/api/config', (req, res) => {
    const [config, source] = loadConfigFile();
    res.json({
        hasConfig: !!config,
        source: source,
        organizationId: config?.organizationId || null
    });
});

app.get('/api/credentials', (req, res) => {
    const [config, source] = loadConfigFile();
    if (config) {
        res.json({
            hasCredentials: true,
            source: source,
            clientId: config.clientId ? config.clientId.substring(0, 8) + '...' : null,
            organizationId: config.organizationId
        });
    } else {
        res.json({ hasCredentials: false });
    }
});

app.get('/api/session-info', (req, res) => {
    res.json({
        authenticated: appConfig.authenticated,
        organizationId: appConfig.organizationId,
        baseUrl: appConfig.baseUrl,
        isDirectTenant: appConfig.isDirectTenant
    });
});

// =============================================================================
// API ROUTES - Worker Groups
// =============================================================================

app.get('/api/worker-groups', async (req, res) => {
    if (!appConfig.authenticated) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const apiType = req.query.api_type || 'stream';
    const token = appConfig.token;
    const baseUrl = getBaseUrl();

    debugLog(`\n[DEBUG] Fetching worker groups for ${apiType} API...`);
    debugLog(`   Base URL: ${baseUrl}`);

    try {
        let url;
        if (apiType === 'edge') {
            url = `${baseUrl}/api/v1/products/edge/groups`;
        } else {
            url = `${baseUrl}/api/v1/master/groups`;
        }

        debugLog(`   URL: ${url}`);

        const response = await fetch(url, {
            headers: { 'Authorization': `Bearer ${token}` },
            timeout: 10000
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        let groups = [];

        if (apiType === 'edge') {
            if (Array.isArray(data)) {
                groups = data.map(item => ({
                    id: typeof item === 'object' ? (item.id || item) : item,
                    name: typeof item === 'object' ? (item.name || item.id || item) : item
                }));
            } else if (data.items) {
                groups = data.items.map(item => ({
                    id: typeof item === 'object' ? (item.id || item) : item,
                    name: typeof item === 'object' ? (item.name || item.id || item) : item
                }));
            }
        } else if (apiType === 'search') {
            groups = [{ id: 'default_search', name: 'default_search' }];
        } else {
            // Stream - filter out fleets
            const isStreamGroup = (item) => {
                if (typeof item !== 'object') return true;
                const itemId = item.id || '';
                if (itemId.toLowerCase().includes('fleet')) return false;
                if (itemId === 'default_search') return false;
                if (item.product && item.product !== 'stream') return false;
                if (item.isFleet) return false;
                return true;
            };

            if (Array.isArray(data)) {
                groups = data.filter(isStreamGroup).map(item => ({
                    id: typeof item === 'object' ? (item.id || item) : item,
                    name: typeof item === 'object' ? (item.id || item) : item
                }));
            } else if (data.items) {
                groups = data.items.filter(isStreamGroup).map(item => ({
                    id: typeof item === 'object' ? (item.id || item) : item,
                    name: typeof item === 'object' ? (item.id || item) : item
                }));
            }
        }

        // Provide defaults if empty
        if (groups.length === 0) {
            if (apiType === 'search') {
                groups = [{ id: 'default_search', name: 'default_search' }];
            } else {
                groups = [{ id: 'default', name: 'default' }];
            }
        }

        res.json({ groups });
    } catch (e) {
        debugLog(`   [ERROR] ${e.message}`);

        // Return defaults on error
        const defaultGroups = apiType === 'search'
            ? [{ id: 'default_search', name: 'default_search' }]
            : [{ id: 'default', name: 'default' }];

        res.json({ groups: defaultGroups, error: e.message });
    }
});

// =============================================================================
// API ROUTES - Lookups
// =============================================================================

app.get('/api/lookups', async (req, res) => {
    if (!appConfig.authenticated) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const workerGroup = req.query.worker_group || 'default';
    const apiType = req.query.api_type || 'stream';
    const token = appConfig.token;

    try {
        validateWorkerGroup(workerGroup);
        const url = buildApiUrl(apiType, workerGroup, '/system/lookups');

        debugLog(`[LOOKUPS] Fetching from: ${url}`);

        const response = await fetch(url, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }

        const data = await response.json();
        const lookups = data.items || data || [];

        res.json({ lookups });
    } catch (e) {
        debugLog(`[LOOKUPS] Error: ${e.message}`);
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/lookups/:worker_group/:lookup_filename/content', async (req, res) => {
    if (!appConfig.authenticated) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const { worker_group: workerGroup, lookup_filename: lookupFilename } = req.params;
    const apiType = req.query.api_type || 'stream';
    const token = appConfig.token;

    try {
        validateWorkerGroup(workerGroup);
        validateFilename(lookupFilename);

        const url = buildApiUrl(apiType, workerGroup, `/system/lookups/${encodeURIComponent(lookupFilename)}`);

        const response = await fetch(url, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const content = await response.text();
        res.type('text/csv').send(content);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.delete('/api/lookups/:worker_group/:lookup_filename', async (req, res) => {
    if (!appConfig.authenticated) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const { worker_group: workerGroup, lookup_filename: lookupFilename } = req.params;
    const apiType = req.query.api_type || 'stream';
    const token = appConfig.token;

    try {
        validateWorkerGroup(workerGroup);
        validateFilename(lookupFilename);

        const url = buildApiUrl(apiType, workerGroup, `/system/lookups/${encodeURIComponent(lookupFilename)}`);

        const response = await fetch(url, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }

        res.json({ success: true, message: `Deleted ${lookupFilename}` });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// =============================================================================
// API ROUTES - Knowledge Items (Generic)
// =============================================================================

const KNOWLEDGE_TYPE_PATHS = {
    'lookups': '/system/lookups',
    'breakers': '/lib/breakers',
    'datatypes': '/lib/datatypes',
    'parsers': '/lib/parsers',
    'variables': '/lib/vars',
    'macros': '/lib/vars',
    'regexes': '/lib/regexes',
    'grok': '/lib/grok',
    'schemas': '/lib/schemas',
    'parquet-schemas': '/lib/parquet-schemas',
    'database-connections': '/lib/database-connections',
    'hmac': '/lib/hmac-functions',
    'appscope': '/lib/appscope',
    'guard': '/lib/guard'
};

app.get('/api/knowledge/:knowledge_type', async (req, res) => {
    if (!appConfig.authenticated) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const { knowledge_type: knowledgeType } = req.params;
    const workerGroup = req.query.worker_group || 'default';
    const apiType = req.query.api_type || 'stream';
    const token = appConfig.token;

    const apiPath = KNOWLEDGE_TYPE_PATHS[knowledgeType];
    if (!apiPath) {
        return res.status(400).json({ error: `Unknown knowledge type: ${knowledgeType}` });
    }

    try {
        validateWorkerGroup(workerGroup);
        const url = buildApiUrl(apiType, workerGroup, apiPath);

        debugLog(`[KNOWLEDGE] Fetching ${knowledgeType} from: ${url}`);

        const response = await fetch(url, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }

        const data = await response.json();
        const items = data.items || data || [];

        res.json({ items });
    } catch (e) {
        debugLog(`[KNOWLEDGE] Error: ${e.message}`);
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/knowledge/:knowledge_type/:item_id', async (req, res) => {
    if (!appConfig.authenticated) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const { knowledge_type: knowledgeType, item_id: itemId } = req.params;
    const workerGroup = req.query.worker_group || 'default';
    const apiType = req.query.api_type || 'stream';
    const token = appConfig.token;

    const apiPath = KNOWLEDGE_TYPE_PATHS[knowledgeType];
    if (!apiPath) {
        return res.status(400).json({ error: `Unknown knowledge type: ${knowledgeType}` });
    }

    try {
        validateWorkerGroup(workerGroup);
        const url = buildApiUrl(apiType, workerGroup, `${apiPath}/${encodeURIComponent(itemId)}`);

        const response = await fetch(url, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        res.json(data);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/knowledge/:knowledge_type', async (req, res) => {
    if (!appConfig.authenticated) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const { knowledge_type: knowledgeType } = req.params;
    const workerGroup = req.query.worker_group || 'default';
    const apiType = req.query.api_type || 'stream';
    const token = appConfig.token;
    const body = req.body;

    const apiPath = KNOWLEDGE_TYPE_PATHS[knowledgeType];
    if (!apiPath) {
        return res.status(400).json({ error: `Unknown knowledge type: ${knowledgeType}` });
    }

    try {
        validateWorkerGroup(workerGroup);
        const url = buildApiUrl(apiType, workerGroup, apiPath);

        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(body)
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }

        const data = await response.json();
        res.json(data);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.patch('/api/knowledge/:knowledge_type/:item_id', async (req, res) => {
    if (!appConfig.authenticated) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const { knowledge_type: knowledgeType, item_id: itemId } = req.params;
    const workerGroup = req.query.worker_group || 'default';
    const apiType = req.query.api_type || 'stream';
    const token = appConfig.token;
    const body = req.body;

    const apiPath = KNOWLEDGE_TYPE_PATHS[knowledgeType];
    if (!apiPath) {
        return res.status(400).json({ error: `Unknown knowledge type: ${knowledgeType}` });
    }

    try {
        validateWorkerGroup(workerGroup);
        const url = buildApiUrl(apiType, workerGroup, `${apiPath}/${encodeURIComponent(itemId)}`);

        const response = await fetch(url, {
            method: 'PATCH',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(body)
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }

        const data = await response.json();
        res.json(data);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.put('/api/knowledge/:knowledge_type/:item_id', async (req, res) => {
    // Route to PATCH handler
    req.method = 'PATCH';
    return app._router.handle(req, res);
});

app.delete('/api/knowledge/:knowledge_type/:item_id', async (req, res) => {
    if (!appConfig.authenticated) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const { knowledge_type: knowledgeType, item_id: itemId } = req.params;
    const workerGroup = req.query.worker_group || 'default';
    const apiType = req.query.api_type || 'stream';
    const token = appConfig.token;

    const apiPath = KNOWLEDGE_TYPE_PATHS[knowledgeType];
    if (!apiPath) {
        return res.status(400).json({ error: `Unknown knowledge type: ${knowledgeType}` });
    }

    try {
        validateWorkerGroup(workerGroup);
        const url = buildApiUrl(apiType, workerGroup, `${apiPath}/${encodeURIComponent(itemId)}`);

        const response = await fetch(url, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }

        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// =============================================================================
// API ROUTES - Packs
// =============================================================================

app.get('/api/packs', async (req, res) => {
    if (!appConfig.authenticated) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const workerGroup = req.query.worker_group || 'default';
    const apiType = req.query.api_type || 'stream';
    const token = appConfig.token;

    try {
        validateWorkerGroup(workerGroup);
        const url = buildApiUrl(apiType, workerGroup, '/packs');

        const response = await fetch(url, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        const packs = data.items || data || [];

        res.json({ packs });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// =============================================================================
// API ROUTES - Transfer
// =============================================================================

app.post('/api/transfer', async (req, res) => {
    if (!appConfig.authenticated) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const {
        source_api_type: sourceApiType,
        source_worker_group: sourceWorkerGroup,
        target_api_type: targetApiType,
        target_worker_groups: targetWorkerGroups,
        knowledge_type: knowledgeType,
        items,
        content
    } = req.body;

    const token = appConfig.token;
    const results = [];

    try {
        // Validate inputs
        validateApiType(sourceApiType);
        validateApiType(targetApiType);
        validateWorkerGroup(sourceWorkerGroup);

        for (const targetGroup of targetWorkerGroups) {
            validateWorkerGroup(targetGroup);
        }

        const apiPath = KNOWLEDGE_TYPE_PATHS[knowledgeType];
        if (!apiPath && knowledgeType !== 'lookups') {
            throw new Error(`Unknown knowledge type: ${knowledgeType}`);
        }

        // Process each item
        for (const item of items) {
            for (const targetGroup of targetWorkerGroups) {
                try {
                    let url, method, body, headers;

                    if (knowledgeType === 'lookups') {
                        // Lookup transfer - upload file content
                        const filename = item.id || item.filename || item;
                        url = buildApiUrl(targetApiType, targetGroup, `/system/lookups/${encodeURIComponent(filename)}`);
                        method = 'PUT';
                        body = content || item.content || '';
                        headers = {
                            'Authorization': `Bearer ${token}`,
                            'Content-Type': 'text/csv'
                        };
                    } else {
                        // Knowledge item transfer - POST/PUT JSON
                        url = buildApiUrl(targetApiType, targetGroup, apiPath);
                        method = 'POST';
                        body = JSON.stringify(item);
                        headers = {
                            'Authorization': `Bearer ${token}`,
                            'Content-Type': 'application/json'
                        };
                    }

                    const response = await fetch(url, { method, headers, body });

                    if (response.ok) {
                        results.push({
                            item: item.id || item,
                            targetGroup,
                            success: true
                        });
                    } else {
                        const errorText = await response.text();
                        results.push({
                            item: item.id || item,
                            targetGroup,
                            success: false,
                            error: `HTTP ${response.status}: ${errorText}`
                        });
                    }
                } catch (e) {
                    results.push({
                        item: item.id || item,
                        targetGroup,
                        success: false,
                        error: e.message
                    });
                }
            }
        }

        const successCount = results.filter(r => r.success).length;
        const failCount = results.filter(r => !r.success).length;

        res.json({
            success: failCount === 0,
            results,
            summary: { success: successCount, failed: failCount }
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// =============================================================================
// API ROUTES - Commit & Deploy
// =============================================================================

app.post('/api/commit', async (req, res) => {
    if (!appConfig.authenticated) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const { worker_group: workerGroup, api_type: apiType, message } = req.body;
    const token = appConfig.token;

    try {
        validateWorkerGroup(workerGroup);
        validateApiType(apiType || 'stream');

        const commitMessage = `${COMMIT_PREFIX} ${message || 'Committed via Knowledge Manager'}`;
        const url = buildApiUrl(apiType || 'stream', workerGroup, '/version/commit');

        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                message: commitMessage,
                effective: true
            })
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }

        const data = await response.json();
        res.json({ success: true, commit: data });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/deploy', async (req, res) => {
    if (!appConfig.authenticated) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const { worker_group: workerGroup, api_type: apiType, version } = req.body;
    const token = appConfig.token;

    try {
        validateWorkerGroup(workerGroup);
        validateApiType(apiType || 'stream');

        const url = buildApiUrl(apiType || 'stream', workerGroup, '/version/deploy');

        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ version: version || 'HEAD' })
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }

        const data = await response.json();
        res.json({ success: true, deploy: data });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// =============================================================================
// API ROUTES - Marketplace (Feeds)
// =============================================================================

app.get('/api/marketplace/providers', (req, res) => {
    res.json({ providers: FEED_PROVIDERS });
});

app.get('/api/marketplace/feeds', (req, res) => {
    const db = getDbConnection();
    const feeds = db.prepare('SELECT * FROM feeds ORDER BY name').all();
    db.close();
    res.json({ feeds });
});

app.post('/api/marketplace/feeds', (req, res) => {
    const { provider_id, name, lookup_filename, schedule_cron, targets, auto_deploy, auth_config } = req.body;

    const db = getDbConnection();
    const result = db.prepare(`
        INSERT INTO feeds (provider_id, name, lookup_filename, schedule_cron, targets, auto_deploy, auth_config, enabled)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0)
    `).run(
        provider_id,
        name,
        lookup_filename,
        schedule_cron || '0 6 * * *',
        JSON.stringify(targets || {}),
        auto_deploy ? 1 : 0,
        auth_config ? JSON.stringify(auth_config) : null
    );

    db.close();
    res.json({ success: true, id: result.lastInsertRowid });
});

app.get('/api/marketplace/feeds/:id', (req, res) => {
    const db = getDbConnection();
    const feed = db.prepare('SELECT * FROM feeds WHERE id = ?').get(req.params.id);
    db.close();

    if (!feed) {
        return res.status(404).json({ error: 'Feed not found' });
    }
    res.json({ feed });
});

app.put('/api/marketplace/feeds/:id', (req, res) => {
    const { name, lookup_filename, schedule_cron, targets, auto_deploy, enabled, auth_config } = req.body;

    const db = getDbConnection();
    db.prepare(`
        UPDATE feeds SET
            name = COALESCE(?, name),
            lookup_filename = COALESCE(?, lookup_filename),
            schedule_cron = COALESCE(?, schedule_cron),
            targets = COALESCE(?, targets),
            auto_deploy = COALESCE(?, auto_deploy),
            enabled = COALESCE(?, enabled),
            auth_config = COALESCE(?, auth_config),
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    `).run(
        name,
        lookup_filename,
        schedule_cron,
        targets ? JSON.stringify(targets) : null,
        auto_deploy !== undefined ? (auto_deploy ? 1 : 0) : null,
        enabled !== undefined ? (enabled ? 1 : 0) : null,
        auth_config ? JSON.stringify(auth_config) : null,
        req.params.id
    );

    db.close();
    res.json({ success: true });
});

app.delete('/api/marketplace/feeds/:id', (req, res) => {
    const db = getDbConnection();
    db.prepare('DELETE FROM feeds WHERE id = ?').run(req.params.id);
    db.close();
    res.json({ success: true });
});

// =============================================================================
// API ROUTES - Snapshots
// =============================================================================

app.get('/api/snapshots', (req, res) => {
    const db = getDbConnection(SNAPSHOTS_DB_PATH);
    const snapshots = db.prepare(`
        SELECT s.*, GROUP_CONCAT(DISTINCT sc.config_type) as config_types
        FROM snapshots s
        LEFT JOIN snapshot_configs sc ON sc.snapshot_id = s.id
        GROUP BY s.id
        ORDER BY s.created_at DESC
    `).all();
    db.close();
    res.json({ snapshots });
});

app.post('/api/snapshots', async (req, res) => {
    if (!appConfig.authenticated) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    const { name, description, worker_group: workerGroup, api_type: apiType, config_types: configTypes } = req.body;
    const token = appConfig.token;

    try {
        validateWorkerGroup(workerGroup);

        const configs = {};

        // Fetch each requested config type
        for (const configType of configTypes) {
            const apiPath = KNOWLEDGE_TYPE_PATHS[configType];
            if (apiPath) {
                const url = buildApiUrl(apiType, workerGroup, apiPath);
                const response = await fetch(url, {
                    headers: { 'Authorization': `Bearer ${token}` }
                });

                if (response.ok) {
                    const data = await response.json();
                    configs[configType] = data.items || data || [];
                }
            }
        }

        // Save to database
        const db = getDbConnection(SNAPSHOTS_DB_PATH);
        const configCount = Object.values(configs).reduce((sum, arr) =>
            sum + (Array.isArray(arr) ? arr.length : 1), 0);
        const sizeBytes = JSON.stringify(configs).length;

        const result = db.prepare(`
            INSERT INTO snapshots (name, description, source_org_id, worker_group, product, config_count, size_bytes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(name, description, appConfig.organizationId, workerGroup, apiType, configCount, sizeBytes);

        const snapshotId = result.lastInsertRowid;

        // Save configs
        const insertConfig = db.prepare(`
            INSERT INTO snapshot_configs (snapshot_id, config_type, config_data, item_count)
            VALUES (?, ?, ?, ?)
        `);

        for (const [configType, configData] of Object.entries(configs)) {
            if (configData) {
                const itemCount = Array.isArray(configData) ? configData.length : 1;
                insertConfig.run(snapshotId, configType, JSON.stringify(configData), itemCount);
            }
        }

        db.close();
        res.json({ success: true, id: snapshotId });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/snapshots/:id', (req, res) => {
    const db = getDbConnection(SNAPSHOTS_DB_PATH);
    const snapshot = db.prepare('SELECT * FROM snapshots WHERE id = ?').get(req.params.id);

    if (!snapshot) {
        db.close();
        return res.status(404).json({ error: 'Snapshot not found' });
    }

    const configs = db.prepare('SELECT config_type, config_data FROM snapshot_configs WHERE snapshot_id = ?')
        .all(req.params.id);

    snapshot.configs = {};
    for (const row of configs) {
        snapshot.configs[row.config_type] = JSON.parse(row.config_data);
    }

    db.close();
    res.json({ snapshot });
});

app.delete('/api/snapshots/:id', (req, res) => {
    const db = getDbConnection(SNAPSHOTS_DB_PATH);
    db.prepare('DELETE FROM snapshot_configs WHERE snapshot_id = ?').run(req.params.id);
    db.prepare('DELETE FROM snapshots WHERE id = ?').run(req.params.id);
    db.close();
    res.json({ success: true });
});

// =============================================================================
// API ROUTES - Migration
// =============================================================================

app.post('/api/org-migration/test-connection', async (req, res) => {
    const { client_id: clientId, client_secret: clientSecret, organization_id: organizationId } = req.body;

    try {
        const token = await getBearerToken(clientId, clientSecret);
        const [orgId, baseUrl] = extractOrgIdAndBaseUrl(organizationId);

        // Test connection by listing worker groups
        const url = `${baseUrl}/api/v1/master/groups`;
        const response = await fetch(url, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.ok) {
            res.json({ success: true, message: 'Connection successful' });
        } else {
            throw new Error(`HTTP ${response.status}`);
        }
    } catch (e) {
        res.status(400).json({ success: false, error: e.message });
    }
});

app.post('/api/org-migration/workspaces', async (req, res) => {
    const { client_id: clientId, client_secret: clientSecret, organization_id: organizationId } = req.body;

    try {
        const token = await getBearerToken(clientId, clientSecret);
        const [orgId, baseUrl] = extractOrgIdAndBaseUrl(organizationId);

        const url = `${baseUrl}/api/v1/master/groups`;
        const response = await fetch(url, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();
        const groups = Array.isArray(data) ? data : (data.items || []);

        res.json({
            workspaces: groups.map(g => ({
                id: typeof g === 'object' ? g.id : g,
                name: typeof g === 'object' ? (g.name || g.id) : g
            }))
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// =============================================================================
// STARTUP
// =============================================================================

function startServer() {
    // Initialize databases
    initMarketplaceDb();
    initMigrationHistoryDb();
    initSnapshotsDb();

    // Start server
    app.listen(PORT, () => {
        console.log(`\n[Cribl Knowledge Manager] Server running on http://localhost:${PORT}`);
        console.log('[INFO] Press Ctrl+C to stop\n');

        // Auto-open browser (optional)
        if (process.platform === 'darwin') {
            try {
                execSync(`open http://localhost:${PORT}`, { stdio: 'ignore' });
            } catch (e) {
                // Ignore errors
            }
        }
    });
}

startServer();
