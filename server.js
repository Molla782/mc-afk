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

// Function to connect Bedrock client
async function connectBedrockClient(connectionId) {
    const connection = connections[connectionId];
    if (!connection) {
        console.error(`[ERROR] Connection ${connectionId} not found`);
        return;
    }
    
    try {
        console.log(`[INFO] Connecting to Bedrock server ${connection.serverAddress}:${connection.serverPort} as ${connection.username}`);
        const { createClient } = require('bedrock-protocol');
        const useAuthentication = connection.authenticated === true;
        
        let clientOptions = {
            host: connection.serverAddress,
            port: parseInt(connection.serverPort),
            username: connection.username
        };
        
        if (useAuthentication) {
            console.log(`[INFO] Using authenticated mode for Bedrock connection`);
            
            // Find the account in the server-side bedrockAccounts array
            const account = bedrockAccounts.find(acc => acc.username === connection.username);
            
            if (!account || !account.accessToken) {
                console.error(`[ERROR] Could not find authenticated account data (or token) for ${connection.username} on server.`);
                connection.status = 'error';
                connection.error = 'Authentication failed: Server-side account data not found or incomplete. Please re-add the account.';
                return false;
            }
            
            // Set up the authentication flow options
            clientOptions.offline = false;
            clientOptions.authTitle = process.env.MS_CLIENT_ID; // Use the client ID from env
            clientOptions.profilesFolder = path.join(__dirname, '.mc_bedrock_profiles');
            
            // Use "live" flow type instead of "msal"
            clientOptions.flow = "live";
            
            // Create the token cache directory if it doesn't exist
            const profilesDir = clientOptions.profilesFolder;
            if (!fs.existsSync(profilesDir)) {
                fs.mkdirSync(profilesDir, { recursive: true });
            }
            
            // Create a token cache file with the proper format for "live" flow
            const cacheFile = path.join(profilesDir, 'token_cache.json');
            const cacheData = {
                "AccessToken": account.accessToken,
                "RefreshToken": account.refreshToken || "",
                "Username": account.username,
                "ExpiresOn": new Date(Date.now() + 86400000).toISOString() // Set expiry to 24h from now
            };
            
            fs.writeFileSync(cacheFile, JSON.stringify(cacheData, null, 2));
            
            // Point to the cache file
            clientOptions.cacheFile = cacheFile;
            
            console.log(`[DEBUG] Using profilesFolder: ${clientOptions.profilesFolder}`);
            console.log(`[DEBUG] Authentication flow set to "live" with token cache`);
        } else {
            console.log(`[INFO] Using offline mode for Bedrock connection`);
            clientOptions.offline = true;
        }
        
        // Create Bedrock client
        console.log('[DEBUG] Creating Bedrock client with options:', {
            ...clientOptions,
            // Don't log sensitive information
            authTitle: clientOptions.authTitle ? '[REDACTED]' : undefined,
            cacheFile: clientOptions.cacheFile ? '[REDACTED PATH]' : undefined
        });
        
        const client = createClient(clientOptions);
        
        // Store client reference
        connection.client = client;
        
        // Handle connection events
        client.on('spawn', () => {
            console.log(`[INFO] Bedrock client spawned for ${connection.username}`);
            connection.status = 'connected';
            connection.lastActivity = Date.now();
            
            // Add chat message about successful connection
            addChatMessage(connectionId, 'system', `Connected to ${connection.serverAddress}:${connection.serverPort}`);
        });
        
        // Rest of the event handlers remain the same
        client.on('text', (packet) => {
            if (packet.message) {
                console.log(`[CHAT] ${packet.message}`);
                addChatMessage(connectionId, 'server', packet.message);
                connection.lastActivity = Date.now();
            }
        });
        
        client.on('disconnect', (packet) => {
            console.log(`[INFO] Disconnected from Bedrock server: ${packet?.message || 'Unknown reason'}`);
            addChatMessage(connectionId, 'system', `Disconnected: ${packet?.message || 'Unknown reason'}`);
            connection.status = 'disconnected';
            connection.disconnectReason = packet?.message || 'Unknown reason';
        });
        
        client.on('error', (err) => {
            console.error(`[ERROR] Bedrock client error: ${err.message}`);
            connection.status = 'error';
            connection.error = err.message;
            addChatMessage(connectionId, 'system', `Error: ${err.message}`);
        });
        
        return true;
    } catch (error) {
        console.error(`[ERROR] Failed to connect Bedrock client: ${error.message}`, error.stack);
        connection.status = 'error';
        connection.error = `Failed to initialize connection: ${error.message}`;
        return false;
    }
}

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
    
    const authUrl = `https://login.live.com/oauth20_authorize.srf?client_id=${clientId}&response_type=code&redirect_uri=${encodeURIComponent(redirectUri)}&scope=XboxLive.signin%20offline_access&prompt=select_account&login_hint=optional`;   
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

function addChatMessage(connectionId, sender, message) {
    // Make sure the connection exists
    if (!connectionChatMessages.has(connectionId)) {
        connectionChatMessages.set(connectionId, []);
    }
    
    // Add the message
    connectionChatMessages.get(connectionId).push({
        timestamp: Date.now(),
        sender: sender,
        message: message
    });
    
    // Keep only the last 100 messages
    const messages = connectionChatMessages.get(connectionId);
    if (messages.length > 100) {
        connectionChatMessages.set(connectionId, messages.slice(-100));
    }
    
    // Log the message to console
    console.log(`[CHAT][${connectionId}] ${sender}: ${message}`);
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
