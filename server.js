require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const mc = require('minecraft-protocol');
const { v4: uuidv4 } = require('uuid');
const open = require('open').default;
// Add these new imports at the top of the file
const msal = require('@azure/msal-node');
const http = require('http');
const url = require('url');
const mineflayer = require('mineflayer');
const bedrock = require('bedrock-protocol');
const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const { Buffer } = require('buffer');
const dns = require('dns');

const sessionPassword = crypto.randomBytes(8).toString('hex'); // 16-char hex
console.log('🔐 Session password:', sessionPassword);

let authServer = null;
let connectionTimeout = null;
let mineflayerTimeouts = new Map();
let msaAccessToken = null;
let xboxUsername = null;
let authCode = null;
let authError = null;
let javaAccounts = [];
let bedrockMsaAccessToken = null;
let bedrockXboxUsername = null;
let bedrockAuthError = null;
const bedrockAccounts = [];
const connections = {};


// Helper function to identify non-critical errors
function isNonCriticalError(error) {
    if (!error || !error.message) return false;
    
    const nonCriticalPatterns = [
        'PartialReadError',
        'Missing characters in string',
        'Unexpected buffer end',
        'while reading VarInt',
        'Invalid packet',
        'Unknown packet',
        'Read error for undefined',
        'SlotComponent',
        'SlotComponentType',
        'Slot'
    ];
    
    return nonCriticalPatterns.some(pattern => error.message.includes(pattern) || 
                                   (error.stack && error.stack.includes(pattern)));
}

// Initialize Express app
const app = express();
const port = process.env.PORT || 3000;

// Active Minecraft client connections
const activeConnections = new Map();
// Add a new map to store chat messages for each connection
const connectionChatMessages = new Map();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '.')));

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// New endpoint that uses Mineflayer for authentication
app.post('/api/minecraft/connect-mineflayer', (req, res) => {
    try {
        const { serverAddress, serverPort, accountId } = req.body;
        
        // Generate a unique connection ID
        const connectionId = uuidv4();
        
        console.log(`Attempting to connect to ${serverAddress}:${serverPort}`);
        
        // Check if an account ID was provided
        let selectedAccount = null;
        if (accountId) {
            selectedAccount = javaAccounts.find(acc => acc.id === accountId);
            console.log(`Using selected account: ${selectedAccount ? selectedAccount.javaUsername : 'Not found'}`);
        }
        
        // Create bot options with simplified configuration
        const botOptions = {
            host: serverAddress,
            port: parseInt(serverPort) || 25565,
            version: false,
            viewDistance: 'tiny',
            skipValidation: true,
            checkTimeoutInterval: 60 * 1000,
            connectTimeout: 60000,
            respawn: true
        };
        
        // If we have a selected account with an access token, use it
        if (selectedAccount && selectedAccount.accessToken) {
            console.log(`Authentication type: Using saved Microsoft account (${selectedAccount.javaUsername})`);
            botOptions.auth = 'microsoft';
            botOptions.accessToken = selectedAccount.accessToken;
            botOptions.username = selectedAccount.javaUsername;
        } else {
            console.log(`Authentication type: Microsoft (default)`);
            botOptions.auth = 'microsoft';
        }
        
        console.log('Creating Mineflayer bot with options:', JSON.stringify({
            ...botOptions,
            accessToken: botOptions.accessToken ? '[REDACTED]' : undefined
        }, null, 2));
        
        // Create the bot
        const bot = mineflayer.createBot(botOptions);
        
        // Track connection status
        let connectionSuccessful = false;
        
        // Clear any existing timeout for this connection ID
        if (mineflayerTimeouts.has(connectionId)) {
            clearTimeout(mineflayerTimeouts.get(connectionId));
        }
        
        // Set a new timeout
        const timeout = setTimeout(() => {
            if (!connectionSuccessful && !res.headersSent) {
                console.log('Connection timed out');
                res.status(500).json({ error: 'Connection timed out. The server might be blocking bots or your account.' });
                
                // Clean up
                mineflayerTimeouts.delete(connectionId);
                
                // Try to end the bot if it exists
                if (bot) {
                    try {
                        bot.end();
                    } catch (e) {
                        console.error('Error ending bot on timeout:', e);
                    }
                }
            }
        }, 60000);
        
        // Store the timeout
        mineflayerTimeouts.set(connectionId, timeout);
    
        
        bot.on('login', () => {
            console.log(`Successfully connected to the server as ${bot.username}`);
            connectionSuccessful = true;
            
            // Clear the timeout
            if (mineflayerTimeouts.has(connectionId)) {
                clearTimeout(mineflayerTimeouts.get(connectionId));
                mineflayerTimeouts.delete(connectionId);
            }
            
            // Store the connection
            activeConnections.set(connectionId, {
                client: bot,
                startTime: Date.now(),
                serverAddress: serverAddress,
                serverPort: parseInt(serverPort) || 25565
            });
            
            // Initialize chat messages array for this connection
            connectionChatMessages.set(connectionId, []);
            
            // Send success response
            if (!res.headersSent) {
                res.json({
                    status: 'connected',
                    connectionId,
                    username: bot.username
                });
            }
        });
        
        // Rest of the event handlers remain the same
        
        // Add chat message listener
        bot.on('message', (message) => {
            // Format and log the chat message
            const formattedMessage = `[CHAT] ${message.toString()}`;
            console.log('\x1b[32m%s\x1b[0m', formattedMessage); // Green color for chat messages
            
            // Store the message for this connection
            if (!connectionChatMessages.has(connectionId)) {
                connectionChatMessages.set(connectionId, []);
            }
            connectionChatMessages.get(connectionId).push({
                timestamp: Date.now(),
                message: message.toString()
            });
            
            // Keep only the last 100 messages
            const messages = connectionChatMessages.get(connectionId);
            if (messages.length > 100) {
                connectionChatMessages.set(connectionId, messages.slice(-100));
            }
        });
        
        // Handle kicked event
        bot.on('kicked', (reason, loggedIn) => {
            console.log(`Bot was kicked: ${reason}`);
            
            // Clear the timeout
            if (mineflayerTimeouts.has(connectionId)) {
                clearTimeout(mineflayerTimeouts.get(connectionId));
                mineflayerTimeouts.delete(connectionId);
            }
            
            if (!connectionSuccessful && !res.headersSent) {
                res.status(403).json({ 
                    error: `Kicked from server: ${reason}`,
                    details: "The server might be blocking bots or requiring additional verification."
                });
            }
            
            // Clean up the connection
            const connection = activeConnections.get(connectionId);
            if (connection && connection.afkInterval) {
                clearInterval(connection.afkInterval);
            }
            activeConnections.delete(connectionId);
        });
        
        // In the connect-mineflayer endpoint, remove the duplicate function definition
        // and update the error handler:
        
        // Handle errors more gracefully
        bot.on('error', (err) => {
            // Clear the timeout
            if (mineflayerTimeouts.has(connectionId)) {
                clearTimeout(mineflayerTimeouts.get(connectionId));
                mineflayerTimeouts.delete(connectionId);
            }
            
            // Only log critical errors
            if (err && !isNonCriticalError(err)) {
                console.error('Bot error:', err);
                if (!connectionSuccessful && !res.headersSent) {
                    res.status(500).json({ error: `Connection error: ${err.message}` });
                }
            }
        });
        
        bot.on('end', (reason) => {
            console.log(`Bot disconnected: ${reason}`);
            
            // Clear the timeout
            if (mineflayerTimeouts.has(connectionId)) {
                clearTimeout(mineflayerTimeouts.get(connectionId));
                mineflayerTimeouts.delete(connectionId);
            }
            
            if (!connectionSuccessful && !res.headersSent) {
                res.status(500).json({ 
                    error: `Connection ended: ${reason}`,
                    details: "The server might be blocking bots or your connection was interrupted."
                });
            }
            
            // Clean up the connection
            const connection = activeConnections.get(connectionId);
            if (connection && connection.afkInterval) {
                clearInterval(connection.afkInterval);
            }
            activeConnections.delete(connectionId);
        });
        
    } catch (error) {
        console.error('Connection error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Connect to a Minecraft server
app.post('/api/minecraft/connect', (req, res) => {
    try {
        const { serverAddress, serverPort, username, password, afkAction } = req.body;
        
        // Generate a unique connection ID
        const connectionId = uuidv4();
        
        console.log(`Attempting to connect to ${serverAddress}:${serverPort} as ${username}`);
        console.log(`Authentication type: ${password && password.trim() !== '' ? 'Microsoft' : 'Offline'}`);
        
        // In the connect endpoint, modify the authentication logic to always use Microsoft auth
        
        // First, ping the server to get version information
        console.log(`Pinging server ${serverAddress}:${serverPort}...`);
        mc.ping({
            host: serverAddress,
            port: parseInt(serverPort),
            timeout: 10000 // Increase timeout to 10 seconds
        }, (err, pingResults) => {
            if (err) {
                console.error('Ping error:', err);
                console.log(`Server ${serverAddress}:${serverPort} could not be reached. Error: ${err.message}`);
                return res.status(500).json({ error: `Server could not be reached: ${err.message}` });
            }
            
            console.log('Server ping successful!');
            console.log('Server version:', pingResults.version);
            console.log('Server description:', pingResults.description?.text || 'No description');
            console.log('Players online:', pingResults?.players?.online || 0, '/', pingResults?.players?.max || 0);
            
            // Try to determine the protocol version
            let versionToUse;
            try {
                // Use the detected version if possible
                versionToUse = pingResults.version.name;
                console.log(`Detected server version: ${versionToUse}`);
                tryConnect(versionToUse);
            } catch (e) {
                // Fallback to a common version if detection fails
                console.log('Could not detect version, falling back to 1.19.4');
                tryConnect('1.19.4');
            }
        });
        
        // Function to try connecting with a specific version
        function tryConnect(version) {
            // Clean up the version string and handle proxy servers like Velocity
            if (version.includes('Velocity') || version.includes('BungeeCord') || version.includes('Waterfall')) {
                console.log(`Detected proxy server: ${version}, using compatible Minecraft version instead`);
                // Try with a version that's known to be supported by minecraft-protocol
                version = '1.18.2'; // minecraft-protocol supports this version
            }
            
            // Remove any non-version parts (keeping only patterns like 1.x.x)
            const versionMatch = version.match(/(\d+\.\d+(\.\d+)?)/);
            if (versionMatch) {
                version = versionMatch[0];
            } else if (!['1.18.2', '1.17.1', '1.16.5', '1.12.2', '1.8.9'].includes(version)) {
                console.log(`Unrecognized version format: ${version}, falling back to 1.18.2`);
                version = '1.18.2';
            }
            
            console.log(`Trying to connect with version: ${version}`);
            
            // Now create the client with the correct version
            const clientOptions = {
                host: serverAddress,
                port: parseInt(serverPort),
                username: username,
                version: version,
                keepAlive: true,
                skipValidation: true, // Skip some validation to improve compatibility
                checkTimeoutInterval: 60 * 1000, // 60 seconds
                hideErrors: false // Show all errors for debugging
            };
            
            // Always use Microsoft authentication regardless of password
            console.log('Using Microsoft authentication');
            handleMicrosoftAuthWithBrowser(clientOptions, version);
        }
        
// Function to handle Microsoft authentication with browser
function handleMicrosoftAuthWithBrowser(clientOptions, version) {
    console.log('Starting Microsoft authentication flow with browser...');
    
    // Clean up any existing auth server or timeouts
    if (authServer) {
        try {
            authServer.close();
            console.log('Closed existing auth server');
        } catch (err) {
            console.log('Error closing existing auth server:', err.message);
        }
        authServer = null;
    }
    
    if (connectionTimeout) {
        clearTimeout(connectionTimeout);
        connectionTimeout = null;
    }
    
    // Create a local server to receive the auth callback
    authServer = http.createServer();
    const port = 8484; // Use a specific port for the redirect
    
    authServer.listen(port, '0.0.0.0', () => {
        console.log(`Auth callback server listening on port ${port}`);
    });
    
    // Microsoft OAuth parameters
    const clientId = process.env.MS_CLIENT_ID;
    const clientSecret = process.env.MS_CLIENT_SECRET;
    const redirectUri = `https://www.snowwysmp.net:${port}`; // Use the registered redirect URI
    const authUrl = `https://login.live.com/oauth20_authorize.srf?client_id=${clientId}&response_type=code&redirect_uri=${encodeURIComponent(redirectUri)}&scope=XboxLive.signin%20offline_access`;
    
    console.log(`Opening browser for Microsoft authentication: ${authUrl}`);
    console.log('------------------------------------------------------');
    console.log('If the browser does not open automatically, please copy and paste this URL into your browser:');
    console.log(authUrl);
    console.log('------------------------------------------------------');
    
    // Try to open the browser, but don't worry if it fails
    try {
        require('child_process').exec(`start ${authUrl}`);
    } catch (err) {
        console.log(`Could not automatically open browser: ${err.message}`);
    }
    
    // Send the auth URL to the client
    if (!res.headersSent) {
        res.json({
            status: 'auth_required',
            authUrl: authUrl,
            connectionId
        });
    }
    
    // Handle the auth callback
    authServer.on('request', async (req, response) => {
        const parsedUrl = url.parse(req.url, true);
        
        if (parsedUrl.pathname === '/') {
            const code = parsedUrl.query.code;
            
            if (code) {
                console.log('Received auth code, acquiring token...');
                
                // Send a success page to the browser
                response.writeHead(200, { 'Content-Type': 'text/html' });
                response.end(`
                    <html>
                        <head>
                            <title>Authentication Successful</title>
                            <style>
                                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                                h1 { color: #4CAF50; }
                            </style>
                        </head>
                        <body>
                            <h1>Authentication Successful!</h1>
                            <p>You can now close this window and return to the application.</p>
                        </body>
                    </html>
                `);
                
                try {
                    // Exchange code for token - now including the client_secret
                    const tokenResponse = await fetch('https://login.live.com/oauth20_token.srf', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded'
                        },
                        body: new URLSearchParams({
                            client_id: clientId,
                            client_secret: clientSecret, // Add the client secret here
                            code: code,
                            grant_type: 'authorization_code',
                            redirect_uri: redirectUri
                        }).toString()
                    });
                    
                    const tokenData = await tokenResponse.json();
                    
                    if (tokenData.error) {
                        throw new Error(`Token error: ${tokenData.error_description || tokenData.error}`);
                    }
                    
                    console.log('Microsoft token acquired successfully');
                    
                    // Close the server
                    authServer.close();
                    authServer = null;
                    
                    // Use the token to authenticate with Xbox Live and then Minecraft
                    authenticateWithMinecraft(tokenData.access_token, clientOptions, version);
                } catch (error) {
                    console.error('Token acquisition error:', error);
                    authServer.close();
                    authServer = null;
                    
                    if (!res.headersSent) {
                        res.status(500).json({ error: `Authentication failed: ${error.message}` });
                    }
                }
            } else {
                response.writeHead(400, { 'Content-Type': 'text/html' });
                response.end(`
                    <html>
                        <head>
                            <title>Authentication Failed</title>
                            <style>
                                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                                h1 { color: #f44336; }
                            </style>
                        </head>
                        <body>
                            <h1>Authentication Failed</h1>
                            <p>No authorization code was received. Please try again.</p>
                        </body>
                    </html>
                `);
            }
        }
    });
}
        
        // Function to authenticate with Minecraft using Microsoft token
        async function authenticateWithMinecraft(msAccessToken, clientOptions, version) {
            try {
                console.log('Authenticating with Minecraft using Microsoft token...');
                
                // Step 1: Authenticate with Xbox Live
                const xblResponse = await fetch('https://user.auth.xboxlive.com/user/authenticate', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    body: JSON.stringify({
                        Properties: {
                            AuthMethod: 'RPS',
                            SiteName: 'user.auth.xboxlive.com',
                            RpsTicket: `d=${msAccessToken}`
                        },
                        RelyingParty: 'http://auth.xboxlive.com',
                        TokenType: 'JWT'
                    })
                });
                
                const xblData = await xblResponse.json();
                const xblToken = xblData.Token;
                const userHash = xblData.DisplayClaims.xui[0].uhs;
                
                console.log('Xbox Live authentication successful');
                
                // Step 2: Authenticate with XSTS
                const xstsResponse = await fetch('https://xsts.auth.xboxlive.com/xsts/authorize', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    body: JSON.stringify({
                        Properties: {
                            SandboxId: 'RETAIL',
                            UserTokens: [xblToken]
                        },
                        RelyingParty: 'rp://api.minecraftservices.com/',
                        TokenType: 'JWT'
                    })
                });

                if (!xstsResponse.ok) {
                    const errorText = await xstsResponse.text();
                    console.error('[BEDROCK AUTH] XSTS token acquisition failed:', xstsResponse.status, errorText);
                     // Check for specific XSTS errors (e.g., 2148916233 means no Xbox account, 2148916238 child account)
                    if (xstsResponse.status === 401) {
                         const xstsErrorData = JSON.parse(errorText);
                         if (xstsErrorData.XErr === 2148916233) {
                             bedrockAuthError = 'Authentication failed: This Microsoft account is not linked to an Xbox Live account.';
                         } else if (xstsErrorData.XErr === 2148916238) {
                             bedrockAuthError = 'Authentication failed: Child accounts require parental consent or cannot play multiplayer.';
                         } else {
                             bedrockAuthError = `XSTS token acquisition failed (XErr: ${xstsErrorData.XErr || 'Unknown'})`;
                         }
                    } else {
                        bedrockAuthError = `XSTS token acquisition failed (Status: ${xstsResponse.status})`;
                    }
                    return;
                }
                
                const xstsData = await xstsResponse.json();
                const xstsToken = xstsData.Token;
                
                const xstsUserHash = xstsData.DisplayClaims.xui[0].uhs; 
                console.log('[BEDROCK AUTH] XSTS token obtained.');
                
        // Step 3: Authenticate with Minecraft using XSTS token
        console.log('[BEDROCK AUTH] Authenticating with Minecraft services...');
        const mcResponse = await fetch('https://api.minecraftservices.com/authentication/login_with_xbox', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                // Use the user hash from XSTS token and the XSTS token itself
                identityToken: `XBL3.0 x=${xstsUserHash};${xstsToken}` 
            })
        });

        if (!mcResponse.ok) {
            const errorText = await mcResponse.text();
            console.error('[BEDROCK AUTH] Minecraft authentication failed:', mcResponse.status, errorText);
            bedrockAuthError = `Minecraft authentication failed (Status: ${mcResponse.status})`;
            return;
        }
                
        const mcData = await mcResponse.json();
        const mcAccessToken = mcData.access_token; // This is the token needed for Minecraft API calls
        console.log('[BEDROCK AUTH] Minecraft access token obtained.');
                
        // Step 4: Get Minecraft profile (includes username/gamertag)
        console.log('[BEDROCK AUTH] Fetching Minecraft profile...');
        const profileResponse = await fetch('https://api.minecraftservices.com/minecraft/profile', {
            headers: {
                'Authorization': `Bearer ${mcAccessToken}` // Use the Minecraft access token
            }
        });
        
        if (!profileResponse.ok) {
            const errorText = await profileResponse.text();
            console.error('[BEDROCK AUTH] Failed to get Minecraft profile:', profileResponse.status, errorText);
            bedrockAuthError = `Failed to get Minecraft profile (Status: ${profileResponse.status})`;
            return;
        }
        
        const profileData = await profileResponse.json();

if (!profileData.name) {
    console.error('[BEDROCK AUTH] Minecraft profile data does not contain name:', profileData);
    bedrockAuthError = 'Failed to retrieve Xbox Gamertag from Minecraft profile.';
    return;
}

bedrockXboxUsername = profileData.name; // This is the Gamertag
console.log(`[BEDROCK AUTH] Successfully authenticated as: ${bedrockXboxUsername}`);

        // *** Crucial Step: Store the authenticated account details on the server ***
        // This allows connectBedrockClient to find the token later
        const existingAccountIndex = bedrockAccounts.findIndex(acc => acc.username === bedrockXboxUsername);
        const accountData = {
            username: bedrockXboxUsername,
            accessToken: mcAccessToken, // Store the Minecraft token
            lastAuthenticated: Date.now()
            // Add email if you retrieve it
        };

        if (existingAccountIndex > -1) {
            bedrockAccounts[existingAccountIndex] = { ...bedrockAccounts[existingAccountIndex], ...accountData };
            console.log(`[BEDROCK AUTH] Updated existing server-side account for ${bedrockXboxUsername}`);
        } else {
            bedrockAccounts.push({ id: uuidv4(), type: 'bedrock', ...accountData });
            console.log(`[BEDROCK AUTH] Added new server-side account for ${bedrockXboxUsername}`);
        }
        
        // Clear the temporary MSA token now that we have the MC token
        // bedrockMsaAccessToken = null; // Or keep it if needed for refresh tokens later

    } catch (error) {
        console.error('[BEDROCK AUTH] Unexpected error during authentication:', error);
        bedrockAuthError = `An unexpected error occurred: ${error.message}`;
    } finally {
        // Close the auth server if it's still open
        if (authServer) {
            try {
                authServer.close(() => {
                    console.log('[BEDROCK AUTH] Auth callback server closed.');
                    authServer = null;
                });
            } catch (err) {
                console.error('[BEDROCK AUTH] Error closing auth server:', err.message);
                authServer = null;
            }
        }
        // Clear the connection timeout
        if (connectionTimeout) {
            clearTimeout(connectionTimeout);
            connectionTimeout = null;
        }
    }
}
        
        // Function to create and set up the Minecraft client
        function createMinecraftClient(clientOptions, version) {
            try {
                console.log(`Creating Minecraft client with version ${version}...`);
                
                // Create the client
                const client = mc.createClient(clientOptions);
                
                // Set up event handlers
                client.on('connect', () => {
                    console.log('Connected to server!');
                });
                
                client.on('disconnect', (packet) => {
                    console.log('Disconnected from server:', packet?.reason || 'Unknown reason');
                    
                    // Clean up the connection
                    const connection = activeConnections.get(connectionId);
                    if (connection && connection.afkInterval) {
                        clearInterval(connection.afkInterval);
                    }
                    activeConnections.delete(connectionId);
                });
                
                client.on('end', () => {
                    console.log('Connection ended');
                    
                    // Clean up the connection
                    const connection = activeConnections.get(connectionId);
                    if (connection && connection.afkInterval) {
                        clearInterval(connection.afkInterval);
                    }
                    activeConnections.delete(connectionId);
                });
                
                client.on('error', (err) => {
                    // Only log critical errors
                    if (!isNonCriticalError(err)) {
                        console.error('Client error:', err);
                        
                        // Clean up the connection
                        const connection = activeConnections.get(connectionId);
                        if (connection && connection.afkInterval) {
                            clearInterval(connection.afkInterval);
                        }
                        activeConnections.delete(connectionId);
                        
                        if (!res.headersSent) {
                            res.status(500).json({ error: `Connection error: ${err.message}` });
                        }
                    }
                });
                
                client.on('login', (packet) => {
                    console.log('Logged in to server!');
                    
                    // Set up AFK action if specified
                    let afkInterval;
                    if (afkAction && afkAction.enabled) {
                        const interval = 60000; // Default to 1 minute
                        
                        afkInterval = setInterval(() => {
                            try {
                                switch(afkAction.command) {
                                    case 'jump':
                                        // Jump by sending position packets
                                        const pos = client.entity.position;
                                        client.write('position', {
                                            x: pos.x,
                                            y: pos.y + 0.5,
                                            z: pos.z,
                                            onGround: false
                                        });
                                        setTimeout(() => {
                                            client.write('position', {
                                                x: pos.x,
                                                y: pos.y,
                                                z: pos.z,
                                                onGround: true
                                            });
                                        }, 500);
                                        break;
                                    case 'rotate':
                                        // Rotate by sending look packets
                                        const yaw = (client.entity.yaw + 45) % 360;
                                        client.write('look', {
                                            yaw: yaw,
                                            pitch: 0,
                                            onGround: true
                                        });
                                        break;
                                    case 'walk':
                                        // Walk in a small circle
                                        const walkPos = client.entity.position;
                                        const walkYaw = (client.entity.yaw + 15) % 360;
                                        const walkRad = walkYaw * Math.PI / 180;
                                        client.write('look', {
                                            yaw: walkYaw,
                                            pitch: 0,
                                            onGround: true
                                        });
                                        client.write('position', {
                                            x: walkPos.x + Math.sin(walkRad) * 0.2,
                                            y: walkPos.y,
                                            z: walkPos.z + Math.cos(walkRad) * 0.2,
                                            onGround: true
                                        });
                                        break;
                                }
                            } catch (e) {
                                console.error('Error in AFK action:', e);
                            }
                        }, interval);
                    }
                    
                    // Store the connection
                    activeConnections.set(connectionId, {
                        client,
                        afkInterval,
                        startTime: Date.now(),
                        serverAddress: serverAddress,
                        serverPort: parseInt(serverPort) || 25565
                    });
                    
                    // Send success response
                    if (!res.headersSent) {
                        res.json({
                            status: 'connected',
                            connectionId
                        });
                    }
                });
                
            } catch (error) {
                console.error('Client creation error:', error);
                
                if (!res.headersSent) {
                    res.status(500).json({ error: `Failed to create client: ${error.message}` });
                }
            }
        }
        
    } catch (error) {
        console.error('Connection error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Update the active-connections endpoint to include more information
app.get('/api/minecraft/active-connections', (req, res) => {
    try {
        const connections = [];
        
        // Convert the Map to an array of connection objects
        activeConnections.forEach((connection, id) => {
            const bot = connection.client;
            let username = 'Unknown';
            
            // Try to get the username from different possible locations
            if (bot && bot.username) {
                username = bot.username;
            } else if (bot && bot.entity && bot.entity.username) {
                username = bot.entity.username;
            }
            
            connections.push({
                id: id,
                username: username,
                startTime: connection.startTime,
                serverAddress: connection.serverAddress || bot.host || bot.client?.socket?._host,
                serverPort: connection.serverPort || bot.port || bot.client?.socket?._port
            });
        });
        
        res.json({ connections });
    } catch (error) {
        console.error('Error getting active connections:', error);
        res.status(500).json({ error: error.message });
    }
});

// Add a new endpoint to get chat messages
app.get('/api/minecraft/chat/:connectionId', (req, res) => {
    const { connectionId } = req.params;
    
    const connection = activeConnections.get(connectionId);
    if (!connection) {
        return res.status(404).json({ error: 'Connection not found' });
    }
    
    // Return the messages
    res.json({
        messages: connection.messages || []
    });
});

// Disconnect from a Minecraft server
app.post('/api/minecraft/disconnect/:connectionId', async (req, res) => {
    try {
        const connectionId = req.params.connectionId;
        
        if (!activeConnections.has(connectionId)) {
            return res.status(404).json({ error: 'Connection not found' });
        }
        
        const connection = activeConnections.get(connectionId);
        
        // Clean up any intervals
        if (connection.afkInterval) {
            clearInterval(connection.afkInterval);
        }
        
        // End the client connection
        if (connection.client) {
            try {
                connection.client.end();
            } catch (e) {
                console.error('Error ending client:', e);
            }
        }
        
        // Remove the connection from active connections
        activeConnections.delete(connectionId);
        
        // Clear chat messages for this connection
        connectionChatMessages.delete(connectionId);
        
        console.log(`Disconnected from server (${connectionId})`);
        res.json({ status: 'disconnected' });
    } catch (error) {
        console.error('Disconnect error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Keep only this app.listen() call and remove the duplicate one
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
    console.log('Open your browser and navigate to your Render URL to use the Minecraft AFK Client');
});


// Add a diagnostic endpoint
app.get('/api/minecraft/diagnostic', async (req, res) => {
    try {
        console.log('Running diagnostic checks...');
        
        // Check if we can reach Mojang's session server
        const sessionResponse = await fetch('https://sessionserver.mojang.com/session/minecraft/profile/00000000000000000000000000000000', {
            method: 'GET',
            timeout: 5000
        }).catch(err => ({ ok: false, error: err }));
        
        // Check if we can reach Microsoft's authentication endpoint
        const msAuthResponse = await fetch('https://login.live.com/oauth20_authorize.srf', {
            method: 'GET',
            timeout: 5000
        }).catch(err => ({ ok: false, error: err }));
        
        // Check if we can reach the Minecraft API
        const mcApiResponse = await fetch('https://api.minecraftservices.com/minecraft/profile', {
            method: 'GET',
            timeout: 5000
        }).catch(err => ({ ok: false, error: err }));
        
        res.json({
            timestamp: new Date().toISOString(),
            sessionServer: {
                reachable: sessionResponse.ok !== false,
                error: sessionResponse.error ? sessionResponse.error.message : null
            },
            microsoftAuth: {
                reachable: msAuthResponse.ok !== false,
                error: msAuthResponse.error ? msAuthResponse.error.message : null
            },
            minecraftApi: {
                reachable: mcApiResponse.ok !== false,
                error: mcApiResponse.error ? mcApiResponse.error.message : null
            },
            nodeVersion: process.version,
            mineflayerVersion: require('mineflayer/package.json').version,
            minecraftProtocolVersion: require('minecraft-protocol/package.json').version
        });
    } catch (error) {
        console.error('Diagnostic error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Add a new endpoint to reset authentication state
// Update the reset-auth endpoint
app.post('/api/minecraft/reset-auth', (req, res) => {
    try {
        console.log('Resetting authentication state');
        
        // Close any lingering auth servers
        if (authServer) {
            try {
                authServer.close();
                console.log('Closed existing auth server');
            } catch (err) {
                console.log('Error closing existing auth server:', err.message);
            }
            authServer = null;
        }
        
        // Clear global connection timeout
        if (connectionTimeout) {
            clearTimeout(connectionTimeout);
            connectionTimeout = null;
        }
        
        // Clear all mineflayer timeouts
        mineflayerTimeouts.forEach((timeout, id) => {
            clearTimeout(timeout);
        });
        mineflayerTimeouts.clear();
        
        // Try to ensure port is free
        const ports = [8484]; // Auth callback server port
        
        ports.forEach(port => {
            try {
                const tempServer = http.createServer();
                tempServer.listen(port, () => {
                    console.log(`Temporarily binding to port ${port} to ensure it's free`);
                    tempServer.close(() => {
                        console.log(`Released port ${port}`);
                    });
                });
            } catch (err) {
                console.log(`Port ${port} might be in use: ${err.message}`);
            }
        });
        
        res.json({ 
            status: 'success',
            message: 'Authentication state reset',
            timestamp: Date.now()
        });
    } catch (error) {
        console.error('Reset auth error:', error);
        res.status(500).json({ error: error.message });
    }
});
app.post('/api/minecraft/connect-bedrock', (req, res) => {
    const { username, serverAddress, serverPort, useSelectedAccount } = req.body;
    
    if (!username || !serverAddress) {
        return res.status(400).json({
            error: 'Missing parameters',
            message: 'Username and server address are required.'
        });
    }
    
    // Create a unique connection ID
    const connectionId = uuidv4();
    
    // Check if this is an authenticated connection
    // Use the useSelectedAccount flag from the request
    const isAuthenticated = useSelectedAccount === true;
    
    // If authenticated, verify the account exists
    if (isAuthenticated) {
        const account = bedrockAccounts.find(acc => acc.username === username);
        if (!account) {
            return res.status(400).json({
                error: 'Authentication failed',
                message: 'Could not find authenticated account with this username.'
            });
        }
    }
    
    // Store connection details
    connections[connectionId] = {
        type: 'bedrock',
        username: username,
        serverAddress: serverAddress,
        serverPort: serverPort || 19132,
        status: 'connecting',
        client: null,
        lastActivity: Date.now(),
        chatMessages: [],
        authenticated: isAuthenticated
    };
    
    // Start the connection process
    connectBedrockClient(connectionId);
    
    res.json({
        status: 'connecting',
        connectionId: connectionId,
        message: `Connecting to ${serverAddress}:${serverPort || 19132} as ${username} (${isAuthenticated ? 'authenticated' : 'offline'})`
    });
});


app.post('/api/minecraft/send-message/:connectionId', async (req, res) => {
    const connectionId = req.params.connectionId;
    const { message } = req.body;
  
    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }
  
    if (!activeConnections.has(connectionId)) {
      return res.status(404).json({ error: 'Connection not found' });
    }
  
    try {
      const connection = activeConnections.get(connectionId);
      const client = connection.client;
  
      if (!client) {
        return res.status(500).json({ error: 'Client not available' });
      }
  
      // Debug-Log: Ausgabe des aktuellen Client-Zustands
      console.log(`[DEBUG] Client state for connection ${connectionId}:`, {
        uuid: client.uuid,
        entityId: client.entityId,
        xuid: client.xuid,
        edition: connection.edition
      });
  
      if (connection.edition === 'bedrock') {
        console.log(`[DEBUG] Preparing to send Bedrock message: "${message}" for connection ${connectionId}`);
  
        if (message.startsWith('/')) {
          // Für Befehle: Entferne den führenden "/" und erstelle das Command-Paket
          const commandPacket = {
            command: message.slice(1),
            origin: {
              type: 0,
              // Erwartet wird eine UUID als string
              uuid: client.uuid || '00000000-0000-0000-0000-000000000000',
              request_id: 0, // Muss als Zahl übergeben werden
              player_entity_id: Number(client.entityId) || 0
            },
            internal: false,
            version: 0
          };
  
          console.log(`[DEBUG] Sending Bedrock command packet:`, commandPacket);
          client.queue('command_request', commandPacket);
        } else {
          // Für Chat-Nachrichten: Erstelle das Chat-Paket gemäß der erwarteten Feldnamen
          const chatPacket = {
            type: 1, // Chat message
            needs_translation: false,
            source_name: connection.username,  // statt "source"
            message: message,
            parameters: [],
            xuid: client.xuid || '',
            platform_chat_id: '',
            source_platform: 1
          };
  
          console.log(`[DEBUG] Sending Bedrock chat packet:`, chatPacket);
          client.queue('text', chatPacket);
        }
        console.log(`[INFO] Sent Bedrock message for ${connectionId}: ${message}`);
      } else {
        // Für Java-Edition: Sende den Chat über die native Methode
        console.log(`[DEBUG] Sending Java chat message: "${message}" for connection ${connectionId}`);
        client.chat(message);
        console.log(`[INFO] Sent Java message for ${connectionId}: ${message}`);
      }
  
      res.json({ success: true, status: 'sent' });
    } catch (error) {
      console.error('[ERROR] Error sending message:', error);
      res.status(500).json({ error: `Failed to send message: ${error.message}` });
    }
  });
  // Request Microsoft authentication
// Request Microsoft authentication
app.post('/api/minecraft/request-auth', (req, res) => {
    // Microsoft OAuth parameters
    const clientId = process.env.MS_CLIENT_ID;
    const port = 8484; // Use a specific port for the redirect
    
    const redirectUri = `https://www.snowwysmp.net:${port}`;
    
    const authUrl = `https://login.live.com/oauth20_authorize.srf?client_id=${clientId}&response_type=code&redirect_uri=${encodeURIComponent(redirectUri)}&scope=XboxLive.signin%20offline_access&prompt=select_account&login_hint=optional`;     if (authServer) {
        try {
            authServer.close();
            console.log('Closed existing auth server');
        } catch (err) {
            console.log('Error closing existing auth server:', err.message);
        }
        authServer = null;
    }
    
    const sslOptions = {
        key: fs.readFileSync(path.join(__dirname, 'ssl', 'private.key')),
        cert: fs.readFileSync(path.join(__dirname, 'ssl', 'certificate.crt'))
    };
    
    // Create an HTTPS server instead of HTTP
    authServer = https.createServer(sslOptions, (req, res) => {
        const url = new URL(req.url, `https://www.snowwysmp.net:${port}`);
        const code = url.searchParams.get('code');
        
        if (code) {
            // Store the auth code for later use
            authCode = code;
            
            // Send a success page to the browser
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(`
                <html>
                <head>
                    <title>Authentication Successful</title>
                    <style>
                        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                        .success { color: green; font-size: 24px; margin-bottom: 20px; }
                    </style>
                </head>
                <body>
                    <div class="success">Authentication Successful!</div>
                    <p>You can now close this window and return to the Minecraft AFK Client.</p>
                </body>
                </html>
            `);
            
            // Process the auth code to get tokens
            processAuthCode(code);
        } else {
            // Handle error
            res.writeHead(400, { 'Content-Type': 'text/html' });
            res.end(`
                <html>
                <head>
                    <title>Authentication Failed</title>
                    <style>
                        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                        .error { color: red; font-size: 24px; margin-bottom: 20px; }
                    </style>
                </head>
                <body>
                    <div class="error">Authentication Failed</div>
                    <p>Please close this window and try again.</p>
                </body>
                </html>
            `);
        }
    });
    
    authServer.listen(port, '0.0.0.0', () => {
        console.log(`Auth callback server listening on port ${port}`);
    });
    
    // Send the auth URL to the client
    res.json({
        status: 'auth_required',
        authUrl: authUrl
    });
});

// Check authentication status
app.get('/api/minecraft/check-auth', (req, res) => {
    if (msaAccessToken && xboxUsername) {
        // Extract email from username if it looks like an email
        let email = null;
        let javaUsername = null;
        let bedrockUsername = null;
        
        // Handle the new username format (object with java and bedrock properties)
        if (typeof xboxUsername === 'object') {
            bedrockUsername = xboxUsername.bedrock;
            javaUsername = xboxUsername.java;
            
            // Try to extract email from bedrock username if it looks like an email
            if (bedrockUsername && bedrockUsername.includes('@')) {
                email = bedrockUsername;
            }
        } else {
            // Handle the old format (string)
            bedrockUsername = xboxUsername;
            javaUsername = xboxUsername;
            
            // Try to extract email from username if it looks like an email
            if (xboxUsername.includes('@')) {
                email = xboxUsername;
            }
        }
        
        // Check for duplicates before confirming authentication
        if (email) {
            const existingAccount = javaAccounts.find(account => 
                account.email && account.email.toLowerCase() === email.toLowerCase()
            );
            
            if (existingAccount) {
                res.json({
                    status: 'error',
                    error: 'Account already exists',
                    message: 'This Microsoft account has already been added.'
                });
                return;
            }
            
            // Add to accounts if not a duplicate
            javaAccounts.push({
                email: email,
                accessToken: msaAccessToken,
                javaUsername: javaUsername,
                bedrockUsername: bedrockUsername,
                addedAt: new Date().toISOString()
            });
        }
        
        res.json({
            status: 'authenticated',
            username: javaUsername || bedrockUsername,
            javaUsername: javaUsername,
            bedrockUsername: bedrockUsername,
            email: email,
            edition: 'Java Edition'
        });
    } else if (authError) {
        res.json({
            status: 'error',
            error: authError
        });
    } else {
        res.json({
            status: 'pending'
        });
    }
});

function addChatMessage(connectionId, type, message) {
    const connection = connections[connectionId];
    if (!connection) return;
    
    // Initialize chat history if it doesn't exist
    if (!connection.chatHistory) {
        connection.chatHistory = [];
    }
    
    // Add message to chat history
    connection.chatHistory.push({
        type,
        message,
        timestamp: Date.now()
    });
    
    // Limit chat history to 100 messages
    if (connection.chatHistory.length > 100) {
        connection.chatHistory.shift();
    }
    
    // Emit chat message event for WebSocket clients
    if (io) {
        io.to(`connection-${connectionId}`).emit('chat', {
            type,
            message,
            timestamp: Date.now()
        });
    }
}

// Process the auth code to get tokens
// In the processAuthCode function, let's modify how we store user information

async function processAuthCode(code) {
    try {
        // Reset any existing tokens
        msaAccessToken = null;
        xboxUsername = null;
        authError = null;
        
        // Microsoft OAuth parameters
        const clientId = process.env.MS_CLIENT_ID;
        const clientSecret = process.env.MS_CLIENT_SECRET;
        const port = 8484;
        const redirectUri = `https://www.snowwysmp.net:${port}`;
        
        // Exchange code for access token
        console.log('[AUTH] Exchanging code for token...');
        console.log('[AUTH] Code:', code);
        
        const tokenResponse = await fetch('https://login.live.com/oauth20_token.srf', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                client_id: clientId,
                client_secret: clientSecret, // Add client secret here
                code: code,
                grant_type: 'authorization_code',
                redirect_uri: redirectUri
            })
        });
        
        const tokenData = await tokenResponse.json();
        
        if (tokenData.error) {
            console.error('Error getting access token:', tokenData.error_description);
            authError = tokenData.error_description;
            return;
        }
        
        // Store the access token and email (if available)
        msaAccessToken = tokenData.access_token;
        
        // Try to extract email from the token if possible
        let userEmail = null;
        try {
            // Decode the JWT token to get user info
            const tokenParts = tokenData.access_token.split('.');
            if (tokenParts.length >= 2) {
                const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString());
                if (payload.email) {
                    userEmail = payload.email;
                    console.log(`Found email in token: ${userEmail}`);
                }
            }
        } catch (err) {
            console.log('Could not extract email from token:', err.message);
        }
        
        // Get Xbox Live token
        const xblResponse = await fetch('https://user.auth.xboxlive.com/user/authenticate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                Properties: {
                    AuthMethod: 'RPS',
                    SiteName: 'user.auth.xboxlive.com',
                    RpsTicket: `d=${msaAccessToken}`
                },
                RelyingParty: 'http://auth.xboxlive.com',
                TokenType: 'JWT'
            })
        });
        
        const xblData = await xblResponse.json();
        
        if (!xblData.Token) {
            console.error('Error getting Xbox Live token');
            authError = 'Failed to get Xbox Live token';
            return;
        }
        
        // Get Xbox username from the user hash
        const userHash = xblData.DisplayClaims.xui[0].uhs;
    
        
        // Try to get Xbox username from profile, but don't fail if it doesn't work
        try {
            const profileXstsResponse = await fetch('https://xsts.auth.xboxlive.com/xsts/authorize', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({
                    Properties: {
                        SandboxId: 'RETAIL',
                        UserTokens: [xblData.Token]
                    },
                    RelyingParty: 'http://xboxlive.com', // Different from the Minecraft one
                    TokenType: 'JWT'
                })
            });
            
            const profileXstsData = await profileXstsResponse.json();
            
            if (profileXstsData.error) {
                console.error('XSTS Profile Error:', profileXstsData.error);
                xboxUsername = userEmail || 'Xbox User';
            } else {
                // Now use the XSTS token to get the profile
                const profileResponse = await fetch('https://profile.xboxlive.com/users/me/profile/settings?settings=Gamertag', {
                    method: 'GET',
                    headers: {
                        'Authorization': `XBL3.0 x=${userHash};${profileXstsData.Token}`,
                        'Accept': 'application/json',
                        'x-xbl-contract-version': '2'
                    }
                });
                
                // Check if the response is valid before parsing JSON
                if (!profileResponse.ok) {
                    console.log(`Xbox profile API returned status: ${profileResponse.status}`);
                    console.log('Response headers:', Object.fromEntries([...profileResponse.headers]));
                }
                
                const responseText = await profileResponse.text();
                console.log('Xbox profile API response:', responseText);
                
                if (!responseText || responseText.trim() === '') {
                    console.log('Empty response from Xbox profile API, using default username');
                    xboxUsername = userEmail || 'Xbox User';
                } else {
                    // Try to parse the JSON
                    try {
                        const profileData = JSON.parse(responseText);
                        console.log('Parsed profile data:', profileData);
                        
                        if (profileData.profileUsers && profileData.profileUsers[0] && 
                            profileData.profileUsers[0].settings && profileData.profileUsers[0].settings.length > 0) {
                            const gamertag = profileData.profileUsers[0].settings.find(
                                s => s.id === 'Gamertag'
                            );
                            
                            if (gamertag) {
                                // Use email if available, otherwise use gamertag
                                xboxUsername = gamertag.value;
                                console.log(`Got Xbox username: ${xboxUsername}`);
                            } else {
                                xboxUsername = userEmail || 'Xbox User';
                                console.log('Gamertag not found in profile, using email or default username');
                            }
                        } else {
                            xboxUsername = userEmail || 'Xbox User';
                            console.log('Profile structure not as expected, using email or default username');
                        }
                    } catch (jsonError) {
                        console.error('Error parsing profile JSON:', jsonError);
                        xboxUsername = userEmail || 'Xbox User';
                    }
                }
            }
        } catch (profileError) {
            console.error('Error getting Xbox profile:', profileError);
            // Don't fail the whole process if we can't get the username
            xboxUsername = userEmail || 'Xbox User';
        }
        
        // Store the Xbox username (for Bedrock)
        const bedrockUsername = xboxUsername;
        
        // Now get the Minecraft Java profile
        try {
            console.log('Getting Minecraft Java profile...');
            
            // First, get a XSTS token specifically for Minecraft
            const minecraftXstsResponse = await fetch('https://xsts.auth.xboxlive.com/xsts/authorize', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({
                    Properties: {
                        SandboxId: 'RETAIL',
                        UserTokens: [xblData.Token]
                    },
                    RelyingParty: 'rp://api.minecraftservices.com/',
                    TokenType: 'JWT'
                })
            });
            
            const minecraftXstsData = await minecraftXstsResponse.json();
            
            if (minecraftXstsData.error) {
                console.error('XSTS Minecraft Error:', minecraftXstsData.error);
            } else {
                // Get Minecraft access token
                const mcTokenResponse = await fetch('https://api.minecraftservices.com/authentication/login_with_xbox', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        identityToken: `XBL3.0 x=${userHash};${minecraftXstsData.Token}`
                    })
                });
                
                const mcTokenData = await mcTokenResponse.json();
                console.log('Minecraft token response:', mcTokenData);
                
                if (mcTokenData.access_token) {
                    // Get Minecraft profile to get the Java username
                    const mcProfileResponse = await fetch('https://api.minecraftservices.com/minecraft/profile', {
                        method: 'GET',
                        headers: {
                            'Authorization': `Bearer ${mcTokenData.access_token}`
                        }
                    });
                    
                    if (mcProfileResponse.ok) {
                        const mcProfileData = await mcProfileResponse.json();
                        console.log('Minecraft Java profile:', mcProfileData);
                        
                        if (mcProfileData.name) {
                            console.log(`Got Minecraft Java username: ${mcProfileData.name}`);
                            // Store both usernames
                            xboxUsername = {
                                bedrock: bedrockUsername,
                                java: mcProfileData.name
                            };
                        } else {
                            console.log('No Java username found in profile, using Xbox username');
                            xboxUsername = {
                                bedrock: bedrockUsername,
                                java: bedrockUsername
                            };
                        }
                    } else {
                        console.log('Could not get Minecraft profile, status:', mcProfileResponse.status);
                        const responseText = await mcProfileResponse.text();
                        console.log('Minecraft profile response:', responseText);
                        
                        xboxUsername = {
                            bedrock: bedrockUsername,
                            java: bedrockUsername
                        };
                    }
                } else {
                    console.log('Could not get Minecraft token:', mcTokenData.error || 'Unknown error');
                    xboxUsername = {
                        bedrock: bedrockUsername,
                        java: bedrockUsername
                    };
                }
            }
        } catch (mcError) {
            console.error('Error getting Minecraft profile:', mcError);
            // Don't fail the whole process if we can't get the Java username
            xboxUsername = {
                bedrock: bedrockUsername,
                java: bedrockUsername
            };
        }
        
        console.log('Authentication completed successfully');
        
    } catch (error) {
        console.error('Error processing auth code:', error);
        authError = error.message;
    }
}
app.post('/api/minecraft/request-bedrock-auth', (req, res) => {
    // Microsoft OAuth parameters
    const clientId = process.env.MS_CLIENT_ID;
    const port = 8484; // Use a specific port for the redirect
    const redirectUri = `https://www.snowwysmp.net:${port}`;
    
    // Generate a random state for security
    const state = Math.random().toString(36).substring(2, 15);
    
    // Create the authorization URL with a state parameter to identify this as a Bedrock auth request
    const authUrl = `https://login.live.com/oauth20_authorize.srf?client_id=${clientId}&response_type=code&redirect_uri=${encodeURIComponent(redirectUri)}&scope=XboxLive.signin%20offline_access&prompt=select_account&state=bedrock:${state}`;    
    // Display the auth URL prominently in the console
    console.log('\n=================================================================');
    console.log('MICROSOFT AUTHENTICATION URL (COPY AND PASTE IN YOUR BROWSER):');
    console.log(authUrl);
    console.log('=================================================================\n');
    
    if (authServer) {
        try {
            authServer.close();
            console.log('Closed existing auth server');
        } catch (err) {
            console.log('Error closing existing auth server:', err.message);
        }
        authServer = null;
    }

    const sslOptions = {
        key: fs.readFileSync(path.join(__dirname, 'ssl', 'private.key')),
        cert: fs.readFileSync(path.join(__dirname, 'ssl', 'certificate.crt'))
    };
    
    // Create a local server to receive the auth callback
    authServer = https.createServer(sslOptions, (req, res) => {
        const url = new URL(req.url, `https://www.snowwysmp.net:${port}`);
        const code = url.searchParams.get('code');
        const returnedState = url.searchParams.get('state');
        
        if (code && returnedState) {
            // Check if this is a Bedrock auth request
            const isBedrockAuth = returnedState.startsWith('bedrock:');
            
            // Send a success page to the browser
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(`
                <html>
                <head>
                    <title>Authentication Successful</title>
                    <style>
                        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                        .success { color: green; font-size: 24px; margin-bottom: 20px; }
                    </style>
                </head>
                <body>
                    <div class="success">Authentication Successful!</div>
                    <p>You can now close this window and return to the Minecraft AFK Client.</p>
                </body>
                </html>
            `);
            
            // Process the auth code based on the type of request
            if (isBedrockAuth) {
                processBedrockAuthCode(code);
            } else {
                processAuthCode(code);
            }
        } else {
            // Handle error
            res.writeHead(400, { 'Content-Type': 'text/html' });
            res.end(`
                <html>
                <head>
                    <title>Authentication Failed</title>
                    <style>
                        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                        .error { color: red; font-size: 24px; margin-bottom: 20px; }
                    </style>
                </head>
                <body>
                    <div class="error">Authentication Failed</div>
                    <p>Please close this window and try again.</p>
                </body>
                </html>
            `);
        }
    });
    
    authServer.listen(port, '0.0.0.0', () => {
        console.log(`Auth callback server listening on port ${port}`);
    });
    
    // Send the auth URL to the client
    res.json({
        status: 'auth_required',
        authUrl: authUrl
    });
});
// In the check-bedrock-auth endpoint
app.get('/api/minecraft/check-bedrock-auth', (req, res) => {
    if (bedrockAuthError) {
        // If there was an error, report it
        res.json({ status: 'error', error: bedrockAuthError });
        // Clear the error after reporting it once
        bedrockAuthError = null; 
    } else if(bedrockMsaAccessToken && bedrockXboxUsername) {
        // Extract email from username if it looks like an email
        let email = null;
        let username = bedrockXboxUsername; // Use the username directly
        
        // Handle the username format
        if (typeof bedrockXboxUsername === 'object') {
            username = bedrockXboxUsername.bedrock || bedrockXboxUsername;
            
            // Try to extract email from username if it looks like an email
            if (username && username.includes('@')) {
                email = username;
            }
        } else {
            // Try to extract email from username if it looks like an email
            if (bedrockXboxUsername.includes('@')) {
                email = bedrockXboxUsername;
            }
        }
        
        // Check for duplicates before confirming authentication
        if (email) {
            const existingAccount = bedrockAccounts.find(account => 
                account.email && account.email.toLowerCase() === email.toLowerCase()
            );
            
            if (existingAccount) {
                return res.status(400).json({ 
                    error: 'Account already exists', 
                    message: 'This Microsoft account has already been added for Bedrock.' 
                });
            }
        }
        
        // Add to accounts if not a duplicate
        const newAccount = {
            email: email,
            accessToken: bedrockMsaAccessToken,
            username: username,
            addedAt: new Date().toISOString()
        };
        
        bedrockAccounts.push(newAccount);
        console.log(`Added new Bedrock account: ${username}`);
        console.log('Current Bedrock accounts:', bedrockAccounts.map(a => a.username));
        
        // Log the final username being sent
        console.log(`Sending Bedrock username in response: ${username}`);
        
        res.json({
            status: 'authenticated',
            username: username, // Make sure this is the correct username
            email: email,
            edition: 'Bedrock Edition'
        });
    } else if (bedrockAuthError) {
        res.json({
            status: 'error',
            error: bedrockAuthError
        });
    } else {
        res.json({
            status: 'pending'
        });
    }
});
async function processBedrockAuthCode(code) {
    try {
        // Reset any existing tokens
        bedrockMsaAccessToken = null;
        bedrockXboxUsername = null;
        bedrockAuthError = null;
        
        // Microsoft OAuth parameters
        const clientId = process.env.MS_CLIENT_ID;
        const clientSecret = process.env.MS_CLIENT_SECRET;
        const port = 8484;
        const serverDomain = 'www.snowwysmp.net';
        // Update to use https with your domain
        const redirectUri = `https://${serverDomain}:${port}`;
        
        // Exchange code for access token
        console.log('[BEDROCK AUTH] Exchanging code for token...');
        const tokenResponse = await fetch('https://login.live.com/oauth20_token.srf', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                client_id: clientId,
                client_secret: clientSecret, // Added client_secret parameter
                code: code,
                grant_type: 'authorization_code',
                redirect_uri: redirectUri
            })
        });
        
        const tokenData = await tokenResponse.json();
        
        if (tokenData.error) {
            console.error('[BEDROCK AUTH] Error getting access token:', tokenData.error_description);
            bedrockAuthError = `Failed to get access token: ${tokenData.error_description}`; // Set specific error
            return; // Stop the process
        }
        
        // Store the access token and email (if available)
        bedrockMsaAccessToken = tokenData.access_token;
        console.log('[BEDROCK AUTH] Access token obtained.');
        
        // Try to extract email from the token if possible
        let userEmail = null;
        try {
            // Decode the JWT token to get user info
            const tokenParts = tokenData.access_token.split('.');
            if (tokenParts.length >= 2) {
                const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString());
                if (payload.email) {
                    userEmail = payload.email;
                    console.log(`Found email in Bedrock token: ${userEmail}`);
                }
            }
        } catch (err) {
            console.log('Could not extract email from Bedrock token:', err.message);
        }
        
        let defaultUsername = userEmail || 'Bedrock Player';
        bedrockXboxUsername = defaultUsername;
        
        // Step 1: Authenticate with Xbox Live
        console.log('[BEDROCK AUTH] Authenticating with Xbox Live...');
        const xblResponse = await fetch('https://user.auth.xboxlive.com/user/authenticate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                Properties: {
                    AuthMethod: 'RPS',
                    SiteName: 'user.auth.xboxlive.com',
                    RpsTicket: `d=${bedrockMsaAccessToken}` // Use the obtained token
                },
                RelyingParty: 'http://auth.xboxlive.com',
                TokenType: 'JWT'
            })
        });

        if (!xblResponse.ok) {
            const errorText = await xblResponse.text();
            console.error('[BEDROCK AUTH] Xbox Live authentication failed:', xblResponse.status, errorText);
            bedrockAuthError = `Xbox Live authentication failed (Status: ${xblResponse.status})`;
            return;
       }
        
       const xblData = await xblResponse.json();
       const xblToken = xblData.Token;
       const userHash = xblData.DisplayClaims.xui[0].uhs;
       console.log('[BEDROCK AUTH] Xbox Live token obtained.');
        
        if (!xblData.Token) {
            console.error('Error getting Xbox Live token for Bedrock');
            bedrockAuthError = 'Failed to get Xbox Live token';
            return;
        }
        
        
        // Try to get Xbox username from profile
        try {
            console.log('[BEDROCK AUTH] Getting XSTS token...');
            const xstsResponse = await fetch('https://xsts.auth.xboxlive.com/xsts/authorize', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({
                    Properties: {
                        SandboxId: 'RETAIL',
                        UserTokens: [xblToken] // Use the XBL token
                    },
                    RelyingParty: 'rp://api.minecraftservices.com/', // Target Minecraft services
                    TokenType: 'JWT'
                })
            });
            
            const xstsData = await xstsResponse.json();
    
            if (xstsData.error) {
                console.error('XSTS Profile Error for Bedrock:', xstsData.error);
                // Keep the default username we set earlier
            } else {
                // Now use the XSTS token to get the profile
                const profileResponse = await fetch('https://profile.xboxlive.com/users/me/profile/settings?settings=Gamertag', {
                    method: 'GET',
                    headers: {
                        'Authorization': `XBL3.0 x=${userHash};${xstsData.Token}`,
                        'Accept': 'application/json',
                        'x-xbl-contract-version': '2'
                    }
                });
                
                const responseText = await profileResponse.text();
                console.log('Xbox profile API response for Bedrock:', responseText);
                
                if (!responseText || responseText.trim() === '') {
                    console.log('Empty response from Xbox profile API for Bedrock, using default username');
                    // Keep the default username we set earlier
                } else {
                    // Try to parse the JSON
                    try {
                        const profileData = JSON.parse(responseText);
                        console.log('Parsed profile data for Bedrock:', profileData);
                        
                        if (profileData.profileUsers && profileData.profileUsers[0] && 
                            profileData.profileUsers[0].settings && profileData.profileUsers[0].settings.length > 0) {
                            const gamertag = profileData.profileUsers[0].settings.find(
                                s => s.id === 'Gamertag'
                            );
                            
                            if (gamertag) {
                                bedrockXboxUsername = gamertag.value;
                                console.log(`Got Xbox username for Bedrock: ${bedrockXboxUsername}`);
                            }
                            // If no gamertag found, keep the default username we set earlier
                        }
                        // If profile structure not as expected, keep the default username we set earlier
                    } catch (jsonError) {
                        console.error('Error parsing profile JSON for Bedrock:', jsonError);
                        // Keep the default username we set earlier
                    }
                }
            }
        } catch (profileError) {
            console.error('Error getting Xbox profile for Bedrock:', profileError);
            // Keep the default username we set earlier
        }
        
        console.log('Bedrock authentication completed successfully');
        console.log(`Final Bedrock username: ${bedrockXboxUsername}`);
        
    } catch (error) {
        console.error('Error processing Bedrock auth code:', error);
        bedrockAuthError = error.message;
    }
}
app.post('/verify-password', (req, res) => {
    const { password } = req.body;
    if (password === sessionPassword) {
        res.json({ success: true });
    } else {
        res.json({ success: false });
    }
});
// Add or update this endpoint in your server.js file
app.get('/api/minecraft/status/:connectionId', (req, res) => {
    try {
        const connectionId = req.params.connectionId;
        
        // First check in activeConnections (for Java connections)
        if (activeConnections.has(connectionId)) {
            const connection = activeConnections.get(connectionId);
            
            // Get username from the client if available
            let username = 'Unknown';
            if (connection.client && connection.client.username) {
                username = connection.client.username;
            } else if (connection.client && connection.client.entity && connection.client.entity.username) {
                username = connection.client.entity.username;
            }
            
            return res.json({
                status: 'connected',
                username: username,
                serverAddress: connection.serverAddress,
                serverPort: connection.serverPort,
                startTime: connection.startTime
            });
        }
        
        // Then check in connections (for Bedrock connections)
        if (connections && connections[connectionId]) {
            const connection = connections[connectionId];
            
            return res.json({
                status: connection.status === 'connected' ? 'connected' : 'disconnected',
                username: connection.username,
                serverAddress: connection.serverAddress,
                serverPort: connection.serverPort,
                startTime: connection.startTime || Date.now()
            });
        }
        
        // If not found in either, return disconnected
        res.json({ status: 'disconnected' });
    } catch (error) {
        console.error('Error checking connection status:', error);
        res.status(500).json({ error: error.message });
    }
});
function sendUnconnectedPing(connectionId) {
    const connection = connections[connectionId];
    if (!connection || !connection.client) return;
    
    try {
        // Create an unconnected ping packet
        const buffer = Buffer.alloc(1500);
        let offset = 0;
        
        // Packet ID for unconnected ping (0x01)
        buffer.writeUInt8(0x01, offset++);
        
        // Ping ID (timestamp)
        const timestamp = BigInt(Date.now());
        buffer.writeBigUInt64BE(timestamp, offset);
        offset += 8;
        
        // Magic (16 bytes)
        const magic = Buffer.from([0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78]);
        magic.copy(buffer, offset);
        offset += 16;
        
        // Client GUID
        buffer.writeBigUInt64BE(connection.state.clientGuid, offset);
        offset += 8;
        
        // Send the packet
        connection.client.send(buffer.slice(0, offset), connection.state.serverPort, connection.state.serverAddress, (err) => {
            if (err) {
                console.error(`[ERROR] Failed to send unconnected ping: ${err.message}`);
            } else {
                console.log(`[INFO] Sent unconnected ping to ${connection.state.serverAddress}:${connection.state.serverPort}`);
                
                // Set a timeout for the ping response
                connection.state.pingTimeout = setTimeout(() => {
                    console.error(`[ERROR] Ping timeout for ${connection.state.serverAddress}:${connection.state.serverPort}`);
                    connection.status = 'error';
                    connection.error = 'Server did not respond to ping';
                    addChatMessage(connectionId, 'system', `Error: Server did not respond to ping`);
                }, 5000);
            }
        });
    } catch (error) {
        console.error(`[ERROR] Error creating unconnected ping packet: ${error.message}`);
    }
}

// Function to handle incoming Bedrock packets
function handleBedrockPacket(connectionId, data, rinfo) {
    const connection = connections[connectionId];
    if (!connection) return;
    
    connection.lastActivity = Date.now();
    
    try {
        // Read packet ID (first byte)
        const packetId = data.readUInt8(0);
        
        console.log(`[DEBUG] Received packet with ID: 0x${packetId.toString(16)} from ${rinfo.address}:${rinfo.port}`);
        
        // Handle different packet types
        switch (packetId) {
            case 0x1C: // Unconnected Pong
                handleUnconnectedPong(connectionId, data, rinfo);
                break;
            case 0x06: // Open Connection Reply 1
                handleOpenConnectionReply1(connectionId, data, rinfo);
                break;
            case 0x08: // Open Connection Reply 2
                handleOpenConnectionReply2(connectionId, data, rinfo);
                break;
            case 0x10: // Connection Request Accepted
                handleConnectionRequestAccepted(connectionId, data, rinfo);
                break;
            case 0xA0: // NACK (Negative Acknowledgement)
                // Handle NACK - resend packets
                break;
            case 0xC0: // ACK (Acknowledgement)
                // Handle ACK - mark packets as received
                break;
            case 0x80: // Regular packet
            case 0x84: // Reliable packet
            case 0x88: // Ordered packet
            case 0x8C: // Reliable ordered packet
                // Handle game packets
                handleGamePacket(connectionId, data, rinfo);
                break;
            default:
                console.log(`[DEBUG] Unhandled packet type: 0x${packetId.toString(16)}`);
        }
    } catch (error) {
        console.error(`[ERROR] Error handling packet: ${error.message}`);
    }
}

// Function to handle unconnected pong response
function handleUnconnectedPong(connectionId, data, rinfo) {
    const connection = connections[connectionId];
    if (!connection) return;
    
    try {
        // Clear ping timeout
        if (connection.state && connection.state.pingTimeout) {
            clearTimeout(connection.state.pingTimeout);
            connection.state.pingTimeout = null;
        }
        
        // Parse the pong packet
        let offset = 1; // Skip packet ID
        
        // Read ping ID (timestamp)
        const pingId = data.readBigUInt64BE(offset);
        offset += 8;
        
        // Read server GUID
        const serverGuid = data.readBigUInt64BE(offset);
        offset += 8;
        
        // Skip magic (16 bytes)
        offset += 16;
        
        // Read server info
        const serverInfo = data.toString('utf8', offset);
        console.log(`[INFO] Received server info: ${serverInfo}`);
        
        // Parse server info (format: MCPE;Server Name;Protocol Version;MC Version;Player Count;Max Players;Server GUID;...)
        const parts = serverInfo.split(';');
        if (parts.length >= 7) {
            const serverName = parts[1];
            const protocolVersion = parseInt(parts[2]);
            const mcVersion = parts[3];
            const playerCount = parseInt(parts[4]);
            const maxPlayers = parseInt(parts[5]);
            
            console.log(`[INFO] Server: ${serverName}, Version: ${mcVersion}, Players: ${playerCount}/${maxPlayers}`);
            
            // Store server info in connection state
            if (connection.state) {
                connection.state.serverName = serverName;
                connection.state.protocolVersion = protocolVersion;
                connection.state.mcVersion = mcVersion;
                connection.state.playerCount = playerCount;
                connection.state.maxPlayers = maxPlayers;
                connection.state.serverGuid = serverGuid;
            }
            
            // Now send an open connection request
            sendOpenConnectionRequest1(connectionId);
        }
    } catch (error) {
        console.error(`[ERROR] Error handling unconnected pong: ${error.message}`);
    }
}
function sendOpenConnectionRequest1(connectionId) {
    const connection = connections[connectionId];
    if (!connection || !connection.client) return;
    
    try {
        // Create an open connection request 1 packet
        const buffer = Buffer.alloc(1500);
        let offset = 0;
        
        // Packet ID for open connection request 1 (0x05)
        buffer.writeUInt8(0x05, offset++);
        
        // Magic (16 bytes)
        const magic = Buffer.from([0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78]);
        magic.copy(buffer, offset);
        offset += 16;
        
        // Protocol version (0x0A for current RakNet)
        buffer.writeUInt8(0x0A, offset++);
        
        // Padding (enough to reach MTU size)
        const paddingLength = connection.state.mtuSize - offset - 28; // 28 bytes for UDP/IP headers
        buffer.fill(0, offset, offset + paddingLength);
        offset += paddingLength;
        
        // Send the packet
        connection.client.send(buffer.slice(0, offset), connection.state.serverPort, connection.state.serverAddress, (err) => {
            if (err) {
                console.error(`[ERROR] Failed to send open connection request 1: ${err.message}`);
            } else {
                console.log(`[INFO] Sent open connection request 1 to ${connection.state.serverAddress}:${connection.state.serverPort} with MTU size ${connection.state.mtuSize}`);
                
                // Set a timeout for the response
                if (connection.state.openConnectionRequest1Timeout) {
                    clearTimeout(connection.state.openConnectionRequest1Timeout);
                }
                
                connection.state.openConnectionRequest1Timeout = setTimeout(() => {
                    handleOpenConnectionRequest1Timeout(connectionId);
                }, 3000); // 3 seconds timeout
            }
        });
    } catch (error) {
        console.error(`[ERROR] Error creating open connection request 1 packet: ${error.message}`);
    }
}
function handleOpenConnectionReply1(connectionId, data, rinfo) {
    const connection = connections[connectionId];
    if (!connection) return;
    
    try {
        // Clear the timeout
        if (connection.state && connection.state.openConnectionRequest1Timeout) {
            clearTimeout(connection.state.openConnectionRequest1Timeout);
            connection.state.openConnectionRequest1Timeout = null;
        }
        
        // Parse the open connection reply 1 packet
        let offset = 1; // Skip packet ID
        
        // Skip magic (16 bytes)
        offset += 16;
        
        // Read server GUID
        const serverGuid = data.readBigUInt64BE(offset);
        offset += 8;
        
        // Read server security
        const security = data.readUInt8(offset++);
        
        // Read MTU size
        const mtuSize = data.readUInt16BE(offset);
        offset += 2;
        
        console.log(`[INFO] Received open connection reply 1: MTU size = ${mtuSize}, Server GUID = ${serverGuid}`);
        
        // Store MTU size and server GUID in connection state
        if (connection.state) {
            // Cap the MTU size to a reasonable value if it's too large
            // Some servers report incorrect MTU sizes
            const cappedMtuSize = Math.min(mtuSize, 1400);
            if (cappedMtuSize !== mtuSize) {
                console.log(`[INFO] Capping MTU size from ${mtuSize} to ${cappedMtuSize}`);
            }
            
            connection.state.mtuSize = cappedMtuSize;
            connection.state.serverGuid = serverGuid;
            connection.state.security = security === 1;
        }
        
        // Now send an open connection request 2
        sendOpenConnectionRequest2(connectionId);
    } catch (error) {
        console.error(`[ERROR] Error handling open connection reply 1: ${error.message}`);
    }
}
function sendOpenConnectionRequest2(connectionId) {
    const connection = connections[connectionId];
    if (!connection || !connection.client) return;
    
    try {
        // Create an open connection request 2 packet
        const buffer = Buffer.alloc(1500);
        let offset = 0;
        
        // Packet ID for open connection request 2 (0x07)
        buffer.writeUInt8(0x07, offset++);
        
        // Magic (16 bytes)
        const magic = Buffer.from([0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78]);
        magic.copy(buffer, offset);
        offset += 16;
        
        // Server address
        const serverIp = connection.state.serverAddress.split('.');
        if (serverIp.length === 4) {
            // IPv4
            buffer.writeUInt8(4, offset++); // IPv4
            buffer.writeUInt8(parseInt(serverIp[0]), offset++);
            buffer.writeUInt8(parseInt(serverIp[1]), offset++);
            buffer.writeUInt8(parseInt(serverIp[2]), offset++);
            buffer.writeUInt8(parseInt(serverIp[3]), offset++);
            buffer.writeUInt16BE(connection.state.serverPort, offset);
            offset += 2;
        } else {
            // This should not happen now that we resolve domains
            console.error(`[ERROR] Invalid IP address format: ${connection.state.serverAddress}`);
            return;
        }
        
        // MTU size
        buffer.writeUInt16BE(connection.state.mtuSize, offset);
        offset += 2;
        
        // Client GUID
        buffer.writeBigUInt64BE(connection.state.clientGuid, offset);
        offset += 8;
        
        // Send the packet
        connection.client.send(buffer.slice(0, offset), connection.state.serverPort, connection.state.serverAddress, (err) => {
            if (err) {
                console.error(`[ERROR] Failed to send open connection request 2: ${err.message}`);
            } else {
                console.log(`[INFO] Sent open connection request 2 to ${connection.state.serverAddress}:${connection.state.serverPort}`);
            }
        });
    } catch (error) {
        console.error(`[ERROR] Error creating open connection request 2 packet: ${error.message}`);
    }
}

// Function to handle open connection reply 2
function handleOpenConnectionReply2(connectionId, data, rinfo) {
    const connection = connections[connectionId];
    if (!connection) return;
    
    try {
        // Parse the open connection reply 2 packet
        let offset = 1; // Skip packet ID
        
        // Skip magic (16 bytes)
        offset += 16;
        
        // Read server GUID
        const serverGuid = data.readBigUInt64BE(offset);
        offset += 8;
        
        // Read client address
        const addressType = data.readUInt8(offset++);
        offset += addressType === 4 ? 6 : 18; // Skip client address (4 bytes for IPv4 + 2 for port, or 16 bytes for IPv6 + 2 for port)
        
        // Read MTU size
        const mtuSize = data.readUInt16BE(offset);
        offset += 2;
        
        // Read encryption
        const encryption = data.readUInt8(offset++);
        
        console.log(`[INFO] Received open connection reply 2: MTU size = ${mtuSize}, Encryption = ${encryption}`);
        
        // Store MTU size and server GUID in connection state
        if (connection.state) {
            // Use the capped MTU size from reply 1 instead of the one from reply 2
            // This ensures consistency
            console.log(`[INFO] Using MTU size: ${connection.state.mtuSize}`);
            connection.state.serverGuid = serverGuid;
            connection.state.encryption = encryption === 1;
        }
        
        // Now send a connection request
        sendConnectionRequest(connectionId);
        
        // Set a timeout for the connection request accepted
        if (connection.state.connectionRequestTimeout) {
            clearTimeout(connection.state.connectionRequestTimeout);
        }
        
        connection.state.connectionRequestTimeout = setTimeout(() => {
            if (connection.status !== 'connected') {
                console.log(`[INFO] Connection request timeout, retrying...`);
                sendConnectionRequest(connectionId);
            }
        }, 5000); // 5 seconds timeout
    } catch (error) {
        console.error(`[ERROR] Error handling open connection reply 2: ${error.message}`);
    }
}

// Function to send a connection request
// Remove the duplicate function and keep only this improved version
function sendConnectionRequest(connectionId) {
    const connection = connections[connectionId];
    if (!connection || !connection.client) return;
    
    try {
        // Create a connection request packet
        const buffer = Buffer.alloc(1500);
        let offset = 0;
        
        // Packet ID for connection request (0x09)
        buffer.writeUInt8(0x09, offset++);
        
        // Client GUID
        buffer.writeBigUInt64BE(connection.state.clientGuid, offset);
        offset += 8;
        
        // Timestamp
        const timestamp = BigInt(Date.now());
        buffer.writeBigUInt64BE(timestamp, offset);
        offset += 8;
        
        // Security
        buffer.writeUInt8(0, offset++); // No security
        
        // Send the packet
        connection.client.send(buffer.slice(0, offset), connection.state.serverPort, connection.state.serverAddress, (err) => {
            if (err) {
                console.error(`[ERROR] Failed to send connection request: ${err.message}`);
            } else {
                console.log(`[INFO] Sent connection request to ${connection.state.serverAddress}:${connection.state.serverPort}`);
            }
        });
    } catch (error) {
        console.error(`[ERROR] Error creating connection request packet: ${error.message}`);
    }
}

// Function to handle connection request accepted
function handleConnectionRequestAccepted(connectionId, data, rinfo) {
    const connection = connections[connectionId];
    if (!connection) return;
    
    try {
        // Clear the timeout
        if (connection.state && connection.state.connectionRequestTimeout) {
            clearTimeout(connection.state.connectionRequestTimeout);
            connection.state.connectionRequestTimeout = null;
        }
        
        // Parse the connection request accepted packet
        let offset = 1; // Skip packet ID
        
        // Read client address
        const addressType = data.readUInt8(offset++);
        offset += addressType === 4 ? 6 : 18; // Skip client address
        
        // Read system addresses
        for (let i = 0; i < 20; i++) {
            const systemAddressType = data.readUInt8(offset++);
            if (systemAddressType === 4) {
                offset += 6; // IPv4 + port
            } else if (systemAddressType === 6) {
                offset += 18; // IPv6 + port
            }
        }
        
        // Read request timestamp
        const requestTimestamp = data.readBigUInt64BE(offset);
        offset += 8;
        
        // Read accepted timestamp
        const acceptedTimestamp = data.readBigUInt64BE(offset);
        offset += 8;
        
        console.log(`[INFO] Connection request accepted`);
        
        // Store timestamps for later use
        if (connection.state) {
            connection.state.serverTimestamp = acceptedTimestamp;
            connection.state.clientTimestamp = requestTimestamp;
        }
        
        // Send new incoming connection packet
        sendNewIncomingConnection(connectionId, rinfo);
        
        // Update connection state
        if (connection.state) {
            connection.state.connected = true;
            connection.status = 'connected';
        }
        
        // Now start the login sequence
        startLoginSequence(connectionId);
    } catch (error) {
        console.error(`[ERROR] Error handling connection request accepted: ${error.message}`);
    }
}
function sendNewIncomingConnection(connectionId, rinfo) {
    const connection = connections[connectionId];
    if (!connection || !connection.client) return;
    
    const { client, state } = connection;
    
    try {
        // Create a new incoming connection packet
        // Packet ID for new incoming connection is 0x13
        const buffer = Buffer.alloc(1500);
        let offset = 0;
        
        // Packet ID
        buffer.writeUInt8(0x13, offset++);
        
        // Server address
        buffer.writeUInt8(4, offset++); // IPv4
        const serverIp = rinfo.address.split('.');
        buffer.writeUInt8(parseInt(serverIp[0]), offset++);
        buffer.writeUInt8(parseInt(serverIp[1]), offset++);
        buffer.writeUInt8(parseInt(serverIp[2]), offset++);
        buffer.writeUInt8(parseInt(serverIp[3]), offset++);
        buffer.writeUInt16BE(rinfo.port, offset);
        offset += 2;
        
        // System addresses (20 of them)
        for (let i = 0; i < 20; i++) {
            buffer.writeUInt8(4, offset++); // IPv4
            buffer.writeUInt8(0, offset++);
            buffer.writeUInt8(0, offset++);
            buffer.writeUInt8(0, offset++);
            buffer.writeUInt8(0, offset++);
            buffer.writeUInt16BE(0, offset);
            offset += 2;
        }
        
        // Server timestamp
        buffer.writeBigUInt64BE(state.serverTimestamp || BigInt(0), offset);
        offset += 8;
        
        // Client timestamp
        buffer.writeBigUInt64BE(state.clientTimestamp || BigInt(0), offset);
        offset += 8;
        
        // Send the packet
        client.send(buffer.slice(0, offset), state.serverPort, state.serverAddress, (err) => {
            if (err) {
                console.error(`[ERROR] Failed to send new incoming connection: ${err.message}`);
            } else {
                console.log(`[INFO] Sent new incoming connection to ${state.serverAddress}:${state.serverPort}`);
                
                // After sending this, we should start sending ACK packets and handling game packets
                startReliablePacketHandling(connectionId);
            }
        });
    } catch (error) {
        console.error(`[ERROR] Error creating new incoming connection packet: ${error.message}`);
    }
}

// Function to start reliable packet handling
function startReliablePacketHandling(connectionId) {
    const connection = connections[connectionId];
    if (!connection) return;
    
    // Set up ACK interval
    const ackInterval = setInterval(() => {
        sendACK(connectionId);
    }, 100); // Send ACK every 100ms
    
    // Store the interval ID for cleanup
    connection.state.ackInterval = ackInterval;
    
    // Update connection status
    connection.status = 'connected';
    
    // Add chat message about successful connection
    addChatMessage(connectionId, 'system', `Connected to ${connection.serverAddress}:${connection.serverPort}`);
    
    // Start the login sequence
    startLoginSequence(connectionId);
}

// Function to send ACK packets
function sendACK(connectionId) {
    const connection = connections[connectionId];
    if (!connection || !connection.client) return;
    
    const { client, state } = connection;
    
    // Only send ACK if we have received packets
    if (state.lastReceivedSequence < 0) return;
    
    // Create an ACK packet
    // Packet ID for ACK is 0xC0
    const buffer = Buffer.alloc(32);
    let offset = 0;
    
    // Packet ID
    buffer.writeUInt8(0xC0, offset++);
    
    // Number of ACK ranges
    buffer.writeUInt16BE(1, offset);
    offset += 2;
    
    // ACK range (start sequence number)
    buffer.writeUInt24BE(state.lastReceivedSequence, offset);
    offset += 3;
    
    // ACK range (end sequence number)
    buffer.writeUInt24BE(state.lastReceivedSequence, offset);
    offset += 3;
    
    // Send the packet
    client.send(buffer.slice(0, offset), state.serverPort, state.serverAddress, (err) => {
        if (err) {
            console.error(`[ERROR] Failed to send ACK: ${err.message}`);
        }
    });
}

// Function to start the login sequence
async function startLoginSequence(connectionId) {
    const connection = connections[connectionId];
    if (!connection) return;
    
    console.log(`[INFO] Starting login sequence for ${connection.username}`);
    
    // Send login packet
    await sendLoginPacket(connectionId);
}

// Function to send login packet
async function sendLoginPacket(connectionId) {
    const connection = connections[connectionId];
    if (!connection || !connection.client) return;
    
    const { client, state, username } = connection;
    
    try {
        // First, create the login payload
        const loginPayload = await createLoginPayload(username, state.clientGuid);
        
        // Then wrap it in a reliable packet
        const reliablePacket = wrapInReliablePacket(loginPayload, state.reliableFrameIndex++);
        
        // Send the packet
        client.send(reliablePacket, state.serverPort, state.serverAddress, (err) => {
            if (err) {
                console.error(`[ERROR] Failed to send login packet: ${err.message}`);
            } else {
                console.log(`[INFO] Sent login packet for ${username}`);
            }
        });
    } catch (error) {
        console.error(`[ERROR] Error creating login packet: ${error.message}`);
    }
}

// Function to create login payload
async function createLoginPayload(username, clientGuid) {
    const connection = connections.find(conn => conn.state && conn.state.clientGuid === clientGuid);
    
    try {
        // Create a buffer for the login packet
        const buffer = Buffer.alloc(4096); // Larger buffer for JWT tokens
        let offset = 0;
        
        // Packet ID for login
        buffer.writeUInt8(0x01, offset++);
        
        // Protocol version
        buffer.writeInt32BE(622, offset); // Updated protocol version for Bedrock 1.20
        offset += 4;
        
        // Payload length placeholder
        const payloadLengthOffset = offset;
        offset += 4;
        
        // Start of payload
        const payloadStartOffset = offset;
        
        let chainData;
        
        if (connection && connection.msaAccessToken) {
            console.log('[INFO] Using Microsoft authentication for login');
            
            // Get Xbox Live tokens using the Microsoft access token
            const xboxData = await getXboxTokens(connection.msaAccessToken);
            
            if (!xboxData || !xboxData.identityToken || !xboxData.xboxUsername) {
                throw new Error('Failed to get Xbox Live tokens');
            }
            
            // Create the chain data with Xbox Live tokens
            chainData = {
                chain: [
                    xboxData.identityToken
                ]
            };
            
            // Set the Xbox username
            username = xboxData.xboxUsername;
        } else {
            console.log('[INFO] Using offline mode for login');
            // For offline mode, use an empty chain
            chainData = {
                chain: []
            };
        }
        
        // Convert chain data to JSON string
        const chainDataStr = JSON.stringify(chainData);
        
        // Write the chain data length
        buffer.writeUInt32LE(chainDataStr.length, offset);
        offset += 4;
        
        // Write the chain data
        buffer.write(chainDataStr, offset);
        offset += chainDataStr.length;
        
        // Create client data JWT
        const clientData = {
            ClientRandomId: Math.floor(Math.random() * 10000000000),
            ServerAddress: connection ? `${connection.serverAddress}:${connection.serverPort}` : "",
            SkinId: crypto.randomUUID().replace(/-/g, ""),
            SkinResourcePatch: JSON.stringify({
                geometry: { default: "geometry.humanoid.custom" }
            }),
            ThirdPartyName: username,
            SelfSignedId: crypto.randomUUID().replace(/-/g, ""),
            DeviceModel: "PC",
            DeviceOS: 7, // Windows
            GameVersion: "1.20.0",
            GuiScale: 0,
            LanguageCode: "en_US"
        };
        
        // Convert client data to JWT
        const clientDataJWT = JSON.stringify(clientData);
        
        // Write client data JWT length
        buffer.writeUInt32LE(clientDataJWT.length, offset);
        offset += 4;
        
        // Write client data JWT
        buffer.write(clientDataJWT, offset);
        offset += clientDataJWT.length;
        
        // Update payload length
        const payloadLength = offset - payloadStartOffset;
        buffer.writeUInt32LE(payloadLength, payloadLengthOffset);
        
        return buffer.slice(0, offset);
    } catch (error) {
        console.error(`[ERROR] Error creating login payload: ${error.message}`);
        throw error;
    }
}

// Helper function to get Xbox Live tokens
async function getXboxTokens(msAccessToken) {
    try {
        console.log('[AUTH] Getting Xbox Live tokens...');
        
        // Step 1: Authenticate with Xbox Live
        const xblResponse = await fetch('https://user.auth.xboxlive.com/user/authenticate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                Properties: {
                    AuthMethod: 'RPS',
                    SiteName: 'user.auth.xboxlive.com',
                    RpsTicket: `d=${msAccessToken}`
                },
                RelyingParty: 'http://auth.xboxlive.com',
                TokenType: 'JWT'
            })
        });
        
        const xblData = await xblResponse.json();
        
        if (!xblData.Token) {
            throw new Error('Failed to get Xbox Live token');
        }
        
        const xblToken = xblData.Token;
        const userHash = xblData.DisplayClaims.xui[0].uhs;
        
        console.log('[AUTH] Xbox Live authentication successful');
        
        // Step 2: Authenticate with XSTS
        const xstsResponse = await fetch('https://xsts.auth.xboxlive.com/xsts/authorize', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                Properties: {
                    SandboxId: 'RETAIL',
                    UserTokens: [xblToken]
                },
                RelyingParty: 'rp://api.minecraftservices.com/',
                TokenType: 'JWT'
            })
        });
        
        const xstsData = await xstsResponse.json();
        
        if (xstsData.XErr) {
            const errorCode = xstsData.XErr;
            let errorMessage = 'Xbox Live authentication failed';
            
            if (errorCode === 2148916233) {
                errorMessage = 'The account does not have an Xbox profile';
            } else if (errorCode === 2148916238) {
                errorMessage = 'The account is from a country where Xbox Live is not available';
            }
            
            throw new Error(errorMessage);
        }
        
        if (!xstsData.Token) {
            throw new Error('Failed to get XSTS token');
        }
        
        const xstsToken = xstsData.Token;
        const xboxUsername = xstsData.DisplayClaims.xui[0].gtg || 'Unknown';
        
        console.log(`[AUTH] XSTS authentication successful for ${xboxUsername}`);
        
        // Step 3: Create the identity token for Minecraft
        const identityToken = `XBL3.0 x=${userHash};${xstsToken}`;
        
        return {
            identityToken,
            xboxUsername
        };
    } catch (error) {
        console.error(`[AUTH] Error getting Xbox tokens: ${error.message}`);
        return null;
    }
}

// Function to wrap payload in a reliable packet
function wrapInReliablePacket(payload, reliableFrameIndex) {
    const buffer = Buffer.alloc(payload.length + 16);
    let offset = 0;
    
    // Packet ID for reliable packet (0x84)
    buffer.writeUInt8(0x84, offset++);
    
    // Reliable frame index
    buffer.writeUInt24BE(reliableFrameIndex, offset);
    offset += 3;
    
    // Copy payload
    payload.copy(buffer, offset);
    offset += payload.length;
    
    return buffer.slice(0, offset);
}

// Helper function to write 24-bit integers (not natively supported in Node.js)
Buffer.prototype.writeUInt24BE = function(value, offset) {
    this.writeUInt8((value >> 16) & 0xFF, offset);
    this.writeUInt8((value >> 8) & 0xFF, offset + 1);
    this.writeUInt8(value & 0xFF, offset + 2);
    return offset + 3;
};

// Update the handleBedrockPacket function to handle more packet types
function handleBedrockPacket(connectionId, data, rinfo) {
    const connection = connections[connectionId];
    if (!connection) return;
    
    connection.lastActivity = Date.now();
    
    try {
        // Read packet ID (first byte)
        const packetId = data.readUInt8(0);
        
        console.log(`[DEBUG] Received packet with ID: 0x${packetId.toString(16)} from ${rinfo.address}:${rinfo.port}`);
        
        // Handle different packet types
        switch (packetId) {
            case 0x1C: // Unconnected Pong
                handleUnconnectedPong(connectionId, data, rinfo);
                break;
            case 0x06: // Open Connection Reply 1
                handleOpenConnectionReply1(connectionId, data, rinfo);
                break;
            case 0x08: // Open Connection Reply 2
                handleOpenConnectionReply2(connectionId, data, rinfo);
                break;
            case 0x10: // Connection Request Accepted
                handleConnectionRequestAccepted(connectionId, data, rinfo);
                break;
            case 0xA0: // NACK (Negative Acknowledgement)
                // Handle NACK - resend packets
                break;
            case 0xC0: // ACK (Acknowledgement)
                // Handle ACK - mark packets as received
                break;
            case 0x80: // Regular packet
            case 0x84: // Reliable packet
            case 0x88: // Ordered packet
            case 0x8C: // Reliable ordered packet
                // Handle game packets
                handleGamePacket(connectionId, data, rinfo);
                break;
            default:
                console.log(`[DEBUG] Unhandled packet type: 0x${packetId.toString(16)}`);
        }
    } catch (error) {
        console.error(`[ERROR] Error handling packet: ${error.message}`);
    }
}

// Function to handle game packets
function handleGamePacket(connectionId, data, rinfo) {
    const connection = connections[connectionId];
    if (!connection) return;
    
    try {
        // Extract the game packet from the reliable packet
        const packetId = data.readUInt8(0);
        let offset = 1;
        
        // If it's a reliable packet, skip the reliable frame index
        if (packetId === 0x84 || packetId === 0x8C) {
            // Skip reliable frame index (3 bytes)
            offset += 3;
        }
        
        // If it's an ordered packet, skip the ordered index and channel
        if (packetId === 0x88 || packetId === 0x8C) {
            // Skip ordered index (3 bytes) and channel (1 byte)
            offset += 4;
        }
        
        // Now we're at the game packet payload
        // Read the game packet ID
        const gamePacketId = data.readUInt8(offset++);
        
        console.log(`[DEBUG] Received game packet with ID: 0x${gamePacketId.toString(16)}`);
        
        // Update the last received sequence number for ACK packets
        if (connection.state) {
            connection.state.lastReceivedSequence = Math.max(
                connection.state.lastReceivedSequence || 0,
                packetId === 0x84 || packetId === 0x8C ? 
                    (data.readUInt8(1) << 16) | (data.readUInt8(2) << 8) | data.readUInt8(3) : 0
            );
        }
        
        // Handle different game packet types
        switch (gamePacketId) {
            case 0x02: // Play Status
                const status = data.readInt32BE(offset);
                console.log(`[INFO] Received Play Status: ${status}`);
                
                if (status === 0) { // Login Success
                    console.log(`[INFO] Login successful for ${connection.username}`);
                    connection.status = 'connected';
                    addChatMessage(connectionId, 'system', `Login successful as ${connection.username}`);
                } else if (status === 1) { // Login Failed - Server Full
                    console.log(`[INFO] Login failed: Server full`);
                    connection.status = 'error';
                    connection.error = 'Server full';
                    addChatMessage(connectionId, 'system', `Error: Server full`);
                } else if (status === 2) { // Login Failed - Invalid Version
                    console.log(`[INFO] Login failed: Invalid version`);
                    connection.status = 'error';
                    connection.error = 'Invalid version';
                    addChatMessage(connectionId, 'system', `Error: Invalid version`);
                } else if (status === 3) { // Already Logged In
                    console.log(`[INFO] Already logged in`);
                    connection.status = 'connected';
                    addChatMessage(connectionId, 'system', `Already logged in as ${connection.username}`);
                } else if (status === 4) { // Login Failed - Server Error
                    console.log(`[INFO] Login failed: Server error`);
                    connection.status = 'error';
                    connection.error = 'Server error';
                    addChatMessage(connectionId, 'system', `Error: Server error`);
                }
                break;
                
            case 0x03: // Start Game
                console.log(`[INFO] Received Start Game packet`);
                // Handle start game packet - extract player position, world info, etc.
                // This is where we would start rendering the world
                break;
                
            case 0x05: // Disconnect
                // Read disconnect reason
                const reasonLength = data.readUInt16BE(offset);
                offset += 2;
                const reason = data.toString('utf8', offset, offset + reasonLength);
                console.log(`[INFO] Disconnected: ${reason}`);
                
                connection.status = 'disconnected';
                connection.error = reason;
                addChatMessage(connectionId, 'system', `Disconnected: ${reason}`);
                break;
                
            case 0x0A: // Text (Chat)
                // Handle chat message
                const type = data.readUInt8(offset++);
                
                // Skip sender information
                if (type === 0) { // Raw
                    // No sender
                } else if (type === 1) { // Chat
                    // Skip sender (variable length string)
                    const senderLength = data.readUInt16BE(offset);
                    offset += 2 + senderLength;
                } else if (type === 2) { // Translation
                    // Skip parameters
                    const paramCount = data.readUInt8(offset++);
                    for (let i = 0; i < paramCount; i++) {
                        const paramLength = data.readUInt16BE(offset);
                        offset += 2 + paramLength;
                    }
                }
                
                // Read message
                const messageLength = data.readUInt16BE(offset);
                offset += 2;
                const message = data.toString('utf8', offset, offset + messageLength);
                
                console.log(`[CHAT] ${message}`);
                addChatMessage(connectionId, 'chat', message);
                break;
                
            default:
                // Ignore other game packets for now
                break;
        }
    } catch (error) {
        console.error(`[ERROR] Error handling game packet: ${error.message}`);
    }
}

// Function to handle chat messages
function handleChatMessage(connectionId, data, offset) {
    const connection = connections[connectionId];
    if (!connection) return;
    
    try {
        // Read message type
        const messageType = data.readUInt8(offset++);
        
        // Skip unused fields
        offset += 1; // Skip needs translation flag
        
        // Read sender
        const senderLength = data.readUInt16BE(offset);
        offset += 2;
        const sender = data.toString('utf8', offset, offset + senderLength);
        offset += senderLength;
        
        // Read message
        const messageLength = data.readUInt16BE(offset);
        offset += 2;
        const message = data.toString('utf8', offset, offset + messageLength);
        
        console.log(`[CHAT] ${sender}: ${message}`);
        addChatMessage(connectionId, sender, message);
    } catch (error) {
        console.error(`[ERROR] Error handling chat message: ${error.message}`);
    }
}
function handleStartGame(connectionId, data, offset) {
    const connection = connections[connectionId];
    if (!connection) return;
    
    try {
        // Parse the Start Game packet
        // This packet contains a lot of information about the game world
        // For simplicity, we'll just extract the entity ID and position
        
        // Entity ID (runtime ID)
        const entityId = data.readVarInt(offset);
        offset = data.lastReadVarIntSize;
        
        // Skip runtime entity ID
        offset = data.readVarInt(offset) + data.lastReadVarIntSize;
        
        // Game mode
        const gameMode = data.readVarInt(offset);
        offset = data.lastReadVarIntSize;
        
        // Player position
        const posX = data.readFloatLE(offset);
        offset += 4;
        const posY = data.readFloatLE(offset);
        offset += 4;
        const posZ = data.readFloatLE(offset);
        offset += 4;
        
        console.log(`[INFO] Player spawned at position: ${posX.toFixed(2)}, ${posY.toFixed(2)}, ${posZ.toFixed(2)}`);
        console.log(`[INFO] Game mode: ${gameMode}`);
        
        // Store entity ID and position in connection state
        if (connection.state) {
            connection.state.entityId = entityId;
            connection.state.position = { x: posX, y: posY, z: posZ };
            connection.state.gameMode = gameMode;
        }
        
        // Send player ready to spawn
        sendPlayerReady(connectionId);
    } catch (error) {
        console.error(`[ERROR] Error handling Start Game packet: ${error.message}`);
    }
}
function sendClientToServerHandshake(connectionId) {
    const connection = connections[connectionId];
    if (!connection || !connection.client) return;
    
    try {
        // Create a Client To Server Handshake packet
        const buffer = Buffer.alloc(5);
        let offset = 0;
        
        // Game packet ID for Client To Server Handshake is 0x04
        buffer.writeUInt8(0x04, offset++);
        
        // Wrap in reliable packet
        const packet = wrapInReliablePacket(buffer.slice(0, offset), connection.state.reliableFrameIndex++);
        
        // Send the packet
        connection.client.send(packet, connection.state.serverPort, connection.state.serverAddress, (err) => {
            if (err) {
                console.error(`[ERROR] Failed to send Client To Server Handshake: ${err.message}`);
            } else {
                console.log(`[INFO] Sent Client To Server Handshake`);
            }
        });
    } catch (error) {
        console.error(`[ERROR] Error creating Client To Server Handshake packet: ${error.message}`);
    }
}
function sendResourcePacksResponse(connectionId) {
    const connection = connections[connectionId];
    if (!connection || !connection.client) return;
    
    try {
        // Create a Resource Packs Response packet
        const buffer = Buffer.alloc(5);
        let offset = 0;
        
        // Game packet ID for Resource Packs Response is 0x08
        buffer.writeUInt8(0x08, offset++);
        
        // Response status (0 = No packs needed)
        buffer.writeUInt8(0x03, offset++);
        
        // Pack IDs count (0)
        buffer.writeUInt16LE(0, offset);
        offset += 2;
        
        // Wrap in reliable packet
        const packet = wrapInReliablePacket(buffer.slice(0, offset), connection.state.reliableFrameIndex++);
        
        // Send the packet
        connection.client.send(packet, connection.state.serverPort, connection.state.serverAddress, (err) => {
            if (err) {
                console.error(`[ERROR] Failed to send Resource Packs Response: ${err.message}`);
            } else {
                console.log(`[INFO] Sent Resource Packs Response`);
            }
        });
    } catch (error) {
        console.error(`[ERROR] Error creating Resource Packs Response packet: ${error.message}`);
    }
}

// Function to send Request Chunk Radius
function sendRequestChunkRadius(connectionId) {
    const connection = connections[connectionId];
    if (!connection || !connection.client) return;
    
    try {
        // Create a Request Chunk Radius packet
        const buffer = Buffer.alloc(5);
        let offset = 0;
        
        // Game packet ID for Request Chunk Radius is 0x45
        buffer.writeUInt8(0x45, offset++);
        
        // Chunk radius (8 chunks)
        buffer.writeInt32LE(8, offset);
        offset += 4;
        
        // Wrap in reliable packet
        const packet = wrapInReliablePacket(buffer.slice(0, offset), connection.state.reliableFrameIndex++);
        
        // Send the packet
        connection.client.send(packet, connection.state.serverPort, connection.state.serverAddress, (err) => {
            if (err) {
                console.error(`[ERROR] Failed to send Request Chunk Radius: ${err.message}`);
            } else {
                console.log(`[INFO] Sent Request Chunk Radius`);
            }
        });
    } catch (error) {
        console.error(`[ERROR] Error creating Request Chunk Radius packet: ${error.message}`);
    }
}

// Function to send Player Ready
function sendPlayerReady(connectionId) {
    const connection = connections[connectionId];
    if (!connection || !connection.client) return;
    
    try {
        // Create a Player Ready packet (SetLocalPlayerAsInitialized)
        const buffer = Buffer.alloc(5);
        let offset = 0;
        
        // Game packet ID for SetLocalPlayerAsInitialized is 0x71
        buffer.writeUInt8(0x71, offset++);
        
        // Runtime entity ID
        buffer.writeVarInt(connection.state.entityId || 0, offset);
        offset += buffer.lastWrittenVarIntSize;
        
        // Wrap in reliable packet
        const packet = wrapInReliablePacket(buffer.slice(0, offset), connection.state.reliableFrameIndex++);
        
        // Send the packet
        connection.client.send(packet, connection.state.serverPort, connection.state.serverAddress, (err) => {
            if (err) {
                console.error(`[ERROR] Failed to send Player Ready: ${err.message}`);
            } else {
                console.log(`[INFO] Sent Player Ready`);
                
                // Now we're fully connected and can start sending movement packets
                connection.status = 'connected';
                addChatMessage(connectionId, 'system', `Fully connected to the server`);
                
                // Start sending movement packets
                startSendingMovementPackets(connectionId);
            }
        });
    } catch (error) {
        console.error(`[ERROR] Error creating Player Ready packet: ${error.message}`);
    }
}

// Function to start sending movement packets
function startSendingMovementPackets(connectionId) {
    const connection = connections[connectionId];
    if (!connection) return;
    
    // Set up movement interval
    const movementInterval = setInterval(() => {
        sendMovementPacket(connectionId);
    }, 1000); // Send movement every second
    
    // Store the interval ID for cleanup
    connection.state.movementInterval = movementInterval;
}

// Function to send movement packet
function sendMovementPacket(connectionId) {
    const connection = connections[connectionId];
    if (!connection || !connection.client || connection.status !== 'connected') return;
    
    try {
        // Create a MovePlayer packet
        const buffer = Buffer.alloc(32);
        let offset = 0;
        
        // Game packet ID for MovePlayer is 0x13
        buffer.writeUInt8(0x13, offset++);
        
        // Runtime entity ID
        buffer.writeVarInt(connection.state.entityId || 0, offset);
        offset += buffer.lastWrittenVarIntSize;
        
        // Position
        const pos = connection.state.position || { x: 0, y: 0, z: 0 };
        buffer.writeFloatLE(pos.x, offset);
        offset += 4;
        buffer.writeFloatLE(pos.y + 1.62, offset); // Eye height
        offset += 4;
        buffer.writeFloatLE(pos.z, offset);
        offset += 4;
        
        // Rotation (pitch, yaw, head yaw)
        buffer.writeFloatLE(0, offset); // Pitch
        offset += 4;
        buffer.writeFloatLE(0, offset); // Yaw
        offset += 4;
        buffer.writeFloatLE(0, offset); // Head Yaw
        offset += 4;
        
        // Mode (0 = normal)
        buffer.writeUInt8(0, offset++);
        
        // On ground
        buffer.writeUInt8(1, offset++);
        
        // Wrap in reliable packet
        const packet = wrapInReliablePacket(buffer.slice(0, offset), connection.state.reliableFrameIndex++);
        
        // Send the packet
        connection.client.send(packet, connection.state.serverPort, connection.state.serverAddress, (err) => {
            if (err) {
                console.error(`[ERROR] Failed to send Movement packet: ${err.message}`);
            }
        });
    } catch (error) {
        console.error(`[ERROR] Error creating Movement packet: ${error.message}`);
    }
}

function sendChatMessage(connectionId, message) {
    const connection = connections[connectionId];
    if (!connection || !connection.client || !connection.state || !connection.state.connected) return;
    
    try {
        // Create a text packet
        const buffer = Buffer.alloc(1024);
        let offset = 0;
        
        // Packet ID for text (0x0A)
        buffer.writeUInt8(0x0A, offset++);
        
        // Type (1 for chat)
        buffer.writeUInt8(1, offset++);
        
        // Skip sender (empty string)
        buffer.writeUInt16BE(0, offset);
        offset += 2;
        
        // Message
        buffer.writeUInt16BE(message.length, offset);
        offset += 2;
        buffer.write(message, offset);
        offset += message.length;
        
        // Wrap in reliable packet
        const reliablePacket = wrapInReliablePacket(buffer.slice(0, offset), connection.state.reliableFrameIndex++);
        
        // Send the packet
        connection.client.send(reliablePacket, connection.state.serverPort, connection.state.serverAddress, (err) => {
            if (err) {
                console.error(`[ERROR] Failed to send chat message: ${err.message}`);
            } else {
                console.log(`[INFO] Sent chat message: ${message}`);
                
                // Add to chat history
                addChatMessage(connectionId, 'self', message);
            }
        });
    } catch (error) {
        console.error(`[ERROR] Error creating chat packet: ${error.message}`);
    }
}

// Add this endpoint to send chat messages
app.post('/api/minecraft/chat/:connectionId', (req, res) => {
    try {
        const connectionId = req.params.connectionId;
        const { message } = req.body;
        
        if (!message || typeof message !== 'string') {
            return res.status(400).json({ error: 'Message is required' });
        }
        
        // Check if connection exists
        if (connections && connections[connectionId]) {
            // Send chat message
            sendChatMessage(connectionId, message);
            
            return res.json({ success: true });
        } else {
            return res.status(404).json({ error: 'Connection not found' });
        }
    } catch (error) {
        console.error('Error sending chat message:', error);
        res.status(500).json({ error: error.message });
    }
});

// Add this endpoint to get chat history
app.get('/api/minecraft/chat/:connectionId', (req, res) => {
    try {
        const connectionId = req.params.connectionId;
        
        // Check if connection exists
        if (connections && connections[connectionId]) {
            // Return chat history
            return res.json({
                chatHistory: connections[connectionId].chatHistory || []
            });
        } else {
            return res.status(404).json({ error: 'Connection not found' });
        }
    } catch (error) {
        console.error('Error getting chat history:', error);
        res.status(500).json({ error: error.message });
    }
});

// Function to clean up connection resources
function cleanupConnection(connectionId) {
    const connection = connections[connectionId];
    if (!connection) return;
    
    // Clear intervals
    if (connection.state) {
        if (connection.state.ackInterval) {
            clearInterval(connection.state.ackInterval);
            connection.state.ackInterval = null;
        }
        
        if (connection.state.movementInterval) {
            clearInterval(connection.state.movementInterval);
            connection.state.movementInterval = null;
        }
    }
    
    // Close UDP socket
    if (connection.client) {
        try {
            connection.client.close();
        } catch (error) {
            console.error(`[ERROR] Error closing UDP socket: ${error.message}`);
        }
        connection.client = null;
    }
    
    console.log(`[INFO] Cleaned up resources for connection ${connectionId}`);
}

// Add VarInt reading/writing methods to Buffer prototype
Buffer.prototype.readVarInt = function(offset) {
    let value = 0;
    let currentByte;
    let byteOffset = 0;
    let isNegative = false;
    
    do {
        currentByte = this.readUInt8(offset + byteOffset);
        
        // Extract the 7 bits of data from the byte
        const byteValue = currentByte & 0x7F;
        value |= byteValue << (7 * byteOffset);
        
        byteOffset++;
        
        // Check if we've read too many bytes
        if (byteOffset > 5) {
            throw new Error('VarInt is too big');
        }
    } while ((currentByte & 0x80) !== 0);
    
    // Store how many bytes we read
    this.lastReadVarIntSize = byteOffset;
    
    return value;
};

Buffer.prototype.writeVarInt = function(value, offset) {
    let byteOffset = 0;
    
    do {
        let byte = value & 0x7F;
        value >>>= 7;
        
        if (value !== 0) {
            byte |= 0x80;
        }
        
        this.writeUInt8(byte, offset + byteOffset);
        byteOffset++;
        
        // Check if we've written too many bytes
        if (byteOffset > 5) {
            throw new Error('VarInt is too big');
        }
    } while (value !== 0);
    
    // Store how many bytes we wrote
    this.lastWrittenVarIntSize = byteOffset;
    
    return offset + byteOffset;
};

// Update the connectBedrockClient function to initialize the state properly
async function connectBedrockClient(connectionId) {
    const connection = connections[connectionId];
    if (!connection) {
        console.error(`[ERROR] Connection ${connectionId} not found`);
        return;
    }
    
    try {
        console.log(`[INFO] Connecting to Bedrock server ${connection.serverAddress}:${connection.serverPort} as ${connection.username}`);
        
        // Resolve domain name to IP address
        try {
            const resolvedAddress = await resolveDomain(connection.serverAddress);
            if (resolvedAddress !== connection.serverAddress) {
                console.log(`[INFO] Using resolved IP address: ${resolvedAddress} for ${connection.serverAddress}`);
                // Store both the original domain and the resolved IP
                connection.originalServerAddress = connection.serverAddress;
                connection.serverAddress = resolvedAddress;
            }
        } catch (error) {
            console.error(`[ERROR] Failed to resolve domain: ${error.message}`);
            connection.status = 'error';
            connection.error = `Failed to resolve domain: ${error.message}`;
            return false;
        }
        
        // Check if Microsoft authentication is needed
        if (connection.useMicrosoftAuth) {
            console.log(`[INFO] Using Microsoft authentication for Bedrock`);
            
            // Make sure we have a token
            if (!bedrockMsaAccessToken) {
                console.error(`[ERROR] No Microsoft access token available for Bedrock`);
                connection.status = 'error';
                connection.error = 'No Microsoft access token available';
                return false;
            }
            
            // Store the token for later use in the login packet
            connection.msaAccessToken = bedrockMsaAccessToken;
            connection.xboxUsername = bedrockXboxUsername;
        }
        
        // Create a UDP socket
        const dgram = require('dgram');
        const client = dgram.createSocket('udp4');
        
        // Store client reference
        connection.client = client;
        connection.status = 'connecting';
        connection.lastActivity = Date.now();
        connection.startTime = Date.now();
        
        // Set up connection state
        const connectionState = {
            serverAddress: connection.serverAddress,
            serverPort: parseInt(connection.serverPort),
            username: connection.username,
            clientGuid: crypto.randomBytes(8).readBigUInt64BE(0),
            mtuSize: 1400, // Default MTU size
            reliableFrameIndex: 0,
            splitPacketCounter: 0,
            fragmentedPackets: new Map(),
            sequenceNumber: 0,
            lastReceivedSequence: -1,
            encryptionEnabled: false,
            authenticated: false,
            entityId: 0,
            position: { x: 0, y: 0, z: 0 },
            gameMode: 0
        };
        
        // Store connection state
        connection.state = connectionState;
        
        // Set up event handlers for the UDP socket
        client.on('message', (msg, rinfo) => {
            handleBedrockPacket(connectionId, msg, rinfo);
        });
        
        client.on('error', (err) => {
            console.error(`[ERROR] Bedrock client socket error: ${err.message}`);
            connection.status = 'error';
            connection.error = err.message;
            addChatMessage(connectionId, 'system', `Error: ${err.message}`);
        });
        
        client.on('close', () => {
            console.log(`[INFO] Bedrock client socket closed`);
            connection.status = 'disconnected';
            addChatMessage(connectionId, 'system', 'Connection closed');
        });
        
        // Bind the socket to a random port
        client.bind(0, () => {
            console.log(`[INFO] UDP socket bound to port ${client.address().port}`);
            
            // Start the connection process by sending an unconnected ping
            sendUnconnectedPing(connectionId);
        });
        
        // Store the connection in activeConnections for later use
        activeConnections.set(connectionId, {
            client: client,
            edition: 'bedrock',
            username: connection.username,
            serverAddress: connection.originalServerAddress || connection.serverAddress,
            serverPort: connection.serverPort,
            messages: [],
            startTime: Date.now()
        });
        
        return true;
    } catch (error) {
        console.error(`[ERROR] Failed to connect Bedrock client: ${error.message}`, error.stack);
        connection.status = 'error';
        connection.error = `Failed to initialize connection: ${error.message}`;
        return false;
    }
}
function debugConnection(connectionId) {
    const connection = connections[connectionId];
    if (!connection) return;
    
    console.log(`[DEBUG] Connection state for ${connectionId}:`);
    console.log(`  Server: ${connection.state.serverAddress}:${connection.state.serverPort}`);
    console.log(`  Status: ${connection.status}`);
    console.log(`  Username: ${connection.username}`);
    console.log(`  Client GUID: ${connection.state.clientGuid}`);
    
    // Set up a timeout to retry the connection if needed
    setTimeout(() => {
        if (connection.status !== 'connected') {
            console.log(`[DEBUG] Connection still not established, retrying open connection request 1...`);
            sendOpenConnectionRequest1(connectionId);
        }
    }, 5000);
}
function retryConnection(connectionId) {
    const connection = connections[connectionId];
    if (!connection) return;
    
    console.log(`[INFO] Retrying connection to ${connection.serverAddress}:${connection.serverPort}`);
    
    // Reset connection state
    connection.status = 'connecting';
    connection.error = null;
    
    // Start the connection process again
    sendUnconnectedPing(connectionId);
    
    // Set up a timeout to check if the connection succeeded
    setTimeout(() => {
        if (connection.status !== 'connected') {
            console.log(`[INFO] Connection still not established after retry`);
        }
    }, 10000);
}

// Add a button to the UI to retry the connection
app.post('/api/minecraft/retry-connection/:connectionId', (req, res) => {
    try {
        const connectionId = req.params.connectionId;
        
        // Check if connection exists
        if (connections && connections[connectionId]) {
            // Retry the connection
            retryConnection(connectionId);
            
            return res.json({ success: true });
        } else {
            return res.status(404).json({ error: 'Connection not found' });
        }
    } catch (error) {
        console.error('Error retrying connection:', error);
        res.status(500).json({ error: error.message });
    }
});
function resolveDomain(domain) {
    return new Promise((resolve, reject) => {
        const dns = require('dns');
        
        // Check if the input is already an IP address
        const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (ipv4Pattern.test(domain)) {
            console.log(`[INFO] Domain is already an IP address: ${domain}`);
            return resolve(domain);
        }
        
        console.log(`[INFO] Resolving domain: ${domain}`);
        
        // Lookup the domain
        dns.lookup(domain, (err, address, family) => {
            if (err) {
                console.error(`[ERROR] Failed to resolve domain ${domain}: ${err.message}`);
                reject(err);
                return;
            }
            
            console.log(`[INFO] Resolved ${domain} to ${address} (IPv${family})`);
            resolve(address);
        });
    });
}
function handleOpenConnectionRequest1Timeout(connectionId) {
    const connection = connections[connectionId];
    if (!connection) return;
    
    console.log(`[INFO] Open connection request 1 timeout for ${connection.state.serverAddress}:${connection.state.serverPort}`);
    
    // Check if we've already tried multiple times
    connection.state.openConnectionRequest1Attempts = (connection.state.openConnectionRequest1Attempts || 0) + 1;
    
    if (connection.state.openConnectionRequest1Attempts < 3) {
        // Try again with a different MTU size
        console.log(`[INFO] Retrying open connection request 1 (attempt ${connection.state.openConnectionRequest1Attempts + 1}) with smaller MTU...`);
        
        // Reduce MTU size for each retry
        const mtuSizes = [1400, 1200, 1000, 800];
        connection.state.mtuSize = mtuSizes[connection.state.openConnectionRequest1Attempts] || 576;
        
        // Send the request again
        sendOpenConnectionRequest1(connectionId);
    } else {
        // After multiple attempts, try a different approach
        console.log(`[INFO] Multiple open connection request 1 attempts failed, trying with minimum MTU...`);
        
        // Try with minimum MTU size as last resort
        connection.state.mtuSize = 576; // Minimum valid MTU size
        connection.state.openConnectionRequest1Attempts = 0; // Reset counter
        
        // Send the request one more time
        sendOpenConnectionRequest1(connectionId);
        
        // Set up a final timeout
        setTimeout(() => {
            if (connection.status !== 'connected') {
                console.log(`[ERROR] Failed to establish connection after multiple attempts`);
                connection.status = 'error';
                connection.error = 'Failed to establish connection with the server';
                addChatMessage(connectionId, 'system', `Error: Failed to establish connection with the server`);
            }
        }, 10000);
    }
}
