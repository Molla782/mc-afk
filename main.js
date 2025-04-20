// Global variables
let currentConnectionId = null;
let statusCheckInterval = null;
let chatCheckInterval = null;
let reconnectAttempts = 0;
const maxReconnectAttempts = 3;
let reconnectTimeout = null;
let uptimeIntervals = [];
let currentEdition = 'java';
let bedrockUsernameInput;
let accounts = [];
let selectedAccount = null;

// DOM elements
let connectButton, disconnectButton, serverAddressInput, serverPortInput;
let statusElement, connectionInfoElement, disconnectContainer;
let chatContainer, chatMessages, chatInput, sendMessageButton;
let accountSelector, addAccountButton, removeAccountButton;
let accountModal, closeModalButton, addAccountForm;
let accountNameInput, accountTypeRadios, bedrockAccountFields, bedrockAccountUsername;

// Initialize DOM references when document is loaded
function initDomReferences() {
    // Existing references
    connectButton = document.getElementById('connect-button');
    disconnectButton = document.getElementById('disconnect-button');
    serverAddressInput = document.getElementById('server-address');
    serverPortInput = document.getElementById('server-port');
    statusElement = document.getElementById('status');
    connectionInfoElement = document.getElementById('connection-info');
    disconnectContainer = document.getElementById('disconnect-container');
    chatContainer = document.getElementById('chat-container');
    chatMessages = document.getElementById('chat-messages');
    chatInput = document.getElementById('chat-input');
    sendMessageButton = document.getElementById('send-message-button');

    // Account management references
    accountSelector = document.getElementById('account-selector');
    addAccountButton = document.getElementById('add-account-button');
    removeAccountButton = document.getElementById('remove-account-button');
    accountModal = document.getElementById('account-modal');
    closeModalButton = document.querySelector('.close-modal');
    addAccountForm = document.getElementById('add-account-form'); // Make sure this is properly referenced
    accountTypeRadios = document.querySelectorAll('input[name="account-type"]');
    bedrockAccountFields = document.getElementById('bedrock-account-fields');
    bedrockAccountUsername = document.getElementById('bedrock-account-username');
    
    // New references for Bedrock support
    bedrockUsernameInput = document.getElementById('bedrock-username');
    
    // Set up edition toggle handlers
    const editionRadios = document.querySelectorAll('input[name="edition"]');
    editionRadios.forEach(radio => {
        radio.addEventListener('change', handleEditionChange);
    });
    
    // Debug log to verify elements are found
    console.log('DOM References initialized:', {
        addAccountButton: !!addAccountButton,
        accountModal: !!accountModal,
        addAccountForm: !!addAccountForm
    });
}

function loadAccounts() {
    try {
        const savedAccounts = localStorage.getItem('minecraft_afk_accounts');
        if (savedAccounts) {
            accounts = JSON.parse(savedAccounts);
            updateAccountSelector();
        }
    } catch (e) {
        console.error('Failed to load accounts from storage:', e);
    }
}

// Save accounts to local storage
function saveAccounts() {
    try {
        localStorage.setItem('minecraft_afk_accounts', JSON.stringify(accounts));
    } catch (e) {
        console.error('Failed to save accounts to storage:', e);
    }
}

// Update the account selector dropdown
// Update the account selector dropdown
function updateAccountSelector() {
    // Clear existing options except the default
    while (accountSelector.options.length > 1) {
        accountSelector.remove(1);
    }
    
    // Add accounts to the selector
    accounts.forEach(account => {
        const option = document.createElement('option');
        option.value = account.id;
        
        // For Java accounts, use email or Xbox username
        if (account.type === 'java') {
            const displayName = account.email || account.xboxUsername || 'Xbox User';
            option.textContent = `${displayName} (Java)`;
        } else {
            // For Bedrock accounts, use the username and ensure it's not undefined
            // Log the account for debugging
            console.log('Bedrock account in selector:', JSON.stringify(account));
            
            // Make sure we're using the correct property and it's not undefined
            const displayName = account.username || 'Bedrock User';
            option.textContent = `${displayName} (Bedrock)`;
        }
        
        accountSelector.appendChild(option);
    });
    
    // Disable remove button if no account is selected
    removeAccountButton.disabled = !accountSelector.value;
}
// Handle account type change in the modal
function handleAccountTypeChange(event) {
    const accountType = event.target.value;
    if (accountType === 'bedrock') {
        bedrockAccountFields.classList.remove('hidden');
    } else {
        bedrockAccountFields.classList.add('hidden');
    }
}

// Account management functions

// Modify the initAccountManagement function to handle Xbox authentication
function initAccountManagement() {
    // Load saved accounts
    loadAccounts();
    
accountSelector.addEventListener('change', function() {
    selectedAccount = this.value ? accounts.find(a => a.id === this.value) : null;
    removeAccountButton.disabled = !selectedAccount;
    
    // Update edition based on selected account
    if (selectedAccount) {
        const editionRadios = document.querySelectorAll('input[name="edition"]');
        for (const radio of editionRadios) {
            if (radio.value === selectedAccount.type) {
                radio.checked = true;
                // Trigger the change event to update UI
                radio.dispatchEvent(new Event('change'));
            }
        }
        
        // For Bedrock accounts, fill in the username
        if (selectedAccount.type === 'bedrock' && selectedAccount.username) {
            bedrockUsernameInput.value = selectedAccount.username;
            
            // Set port to Bedrock default (19132)
            serverPortInput.value = '19132';
        } else if (selectedAccount.type === 'java') {
            // Set port to Java default (25565)
            serverPortInput.value = '25565';
        }
        
        // Update connect button text based on account type
        updateConnectButtonText();
    }
});
    
    addAccountButton.addEventListener('click', function() {
        // Reset form
        addAccountForm.reset();
        bedrockAccountFields.classList.add('hidden');
        
        // Show modal - make sure the display style is explicitly set to 'flex'
        accountModal.style.display = 'flex';
        console.log('Account modal opened'); // Add debug log
    });
    
    removeAccountButton.addEventListener('click', function() {
        if (selectedAccount) {
            if (confirm(`Are you sure you want to remove the account "${selectedAccount.name}"?`)) {
                accounts = accounts.filter(a => a.id !== selectedAccount.id);
                saveAccounts();
                updateAccountSelector();
                selectedAccount = null;
                accountSelector.value = '';
                removeAccountButton.disabled = true;
                
                // Update connect button text
                updateConnectButtonText();
            }
        }
    });
    
    closeModalButton.addEventListener('click', function() {
        accountModal.style.display = 'none';
    });
    
    // Close modal when clicking outside
    window.addEventListener('click', function(event) {
        if (event.target === accountModal) {
            accountModal.style.display = 'none';
        }
    });
    
    // Handle account type change in modal
    accountTypeRadios.forEach(radio => {
        radio.addEventListener('change', handleAccountTypeChange);
    });
    
    // Handle form submission
    addAccountForm.addEventListener('submit', async function(event) {
        event.preventDefault();
        
        const accountType = document.querySelector('input[name="account-type"]:checked').value;
        
        if (accountType === 'bedrock') {
            // For Bedrock accounts, we now have two options:
            // 1. Use a simple username (offline mode)
            // 2. Authenticate with Microsoft (online mode)
            
            // Check if the user wants to use Microsoft authentication
            const useMicrosoftAuth = document.getElementById('bedrock-use-microsoft-auth')?.checked;
            
            if (useMicrosoftAuth) {
                // Use Microsoft authentication flow similar to Java
                try {
                    // Show loading state
                    const submitButton = addAccountForm.querySelector('.submit-button');
                    const originalText = submitButton.textContent;
                    submitButton.textContent = 'Authenticating...';
                    submitButton.disabled = true;
                    
                    // Request Microsoft authentication for Bedrock
                    const response = await fetch('/api/minecraft/request-bedrock-auth', {
                        method: 'POST'
                    });
                    
                    const data = await response.json();
                    
                    if (data.status === 'auth_required' && data.authUrl) {
                        // Open the auth URL in a new window
                        window.open(data.authUrl, '_blank');
                        
                        // Show instructions to the user
                        showToast('Please complete authentication in the opened browser window', 'info', 10000);
                        
                        // Start polling for auth completion
                        let authCheckInterval = setInterval(async () => {
                            try {
                                const checkResponse = await fetch('/api/minecraft/check-bedrock-auth');
                                const checkData = await checkResponse.json();
                                
                                if (checkData.status === 'authenticated') {
                                    clearInterval(authCheckInterval);
                                    
                                    console.log('Bedrock auth successful, server response:', JSON.stringify(checkData));
                                    
                                    // Ensure username exists in the response from the backend
                                    if (!checkData.username) {
                                         console.error('Backend did not return username on successful auth.');
                                         showError('Authentication succeeded but failed to get username.');
                                         // Reset button state
                                         submitButton.textContent = originalText;
                                         submitButton.disabled = false;
                                         return; // Stop processing
                                    }

                                    // Create new account using the username from the backend response
                                    const newAccount = {
                                        id: Date.now().toString(), // Use a more robust ID like UUID if possible
                                        type: 'bedrock',
                                        username: checkData.username, // Use the username from backend
                                        authenticated: true, // Mark as authenticated
                                        createdAt: Date.now(),
                                        lastAuthenticated: Date.now() 
                                        // Email is optional, add if backend provides it
                                        // email: checkData.email 
                                    };
                                    
                                    console.log('Adding Bedrock account to frontend list:', JSON.stringify(newAccount));
                                    
                                    // Check if account already exists in frontend list (by username)
                                    const existingFrontendAccountIndex = accounts.findIndex(acc => acc.username === newAccount.username && acc.type === 'bedrock');
                                    if (existingFrontendAccountIndex > -1) {
                                        // Update existing frontend account if needed (e.g., lastAuthenticated)
                                        accounts[existingFrontendAccountIndex] = { ...accounts[existingFrontendAccountIndex], ...newAccount };
                                        console.log(`Updated existing frontend account for ${newAccount.username}`);
                                    } else {
                                        // Add new account to frontend list
                                        accounts.push(newAccount);
                                        console.log(`Added new frontend account for ${newAccount.username}`);
                                    }

                                    saveAccounts(); // Save updated accounts list to localStorage
                                    updateAccountSelector(); // Refresh dropdown
                                    
                                    // Select the new/updated account
                                    accountSelector.value = newAccount.id;
                                    accountSelector.dispatchEvent(new Event('change')); // Trigger UI updates
                                    
                                    accountModal.style.display = 'none'; // Hide modal
                                    
                                    showToast(`Bedrock account "${newAccount.username}" added/updated successfully`, 'success');
                                    
                                    // Reset button state
                                    submitButton.textContent = originalText;
                                    submitButton.disabled = false;

                                } else if (checkData.status === 'error') {
                                    // Handle error reported by backend
                                    clearInterval(authCheckInterval);
                                    console.error('Bedrock auth failed:', checkData.error);
                                    // Display the specific error from the backend
                                    showError(`Authentication failed: ${checkData.error}`); 
                                    // Reset button state
                                    submitButton.textContent = originalText;
                                    submitButton.disabled = false;
                                }
                                // Continue polling if not authenticated yet
                            } catch (error) {
                                console.error('Error checking auth status:', error);
                            }
                        }, 2000);
                        
                        // Set a timeout to stop polling after 5 minutes
                        setTimeout(() => {
                            if (authCheckInterval) {
                                clearInterval(authCheckInterval);
                                submitButton.textContent = originalText;
                                submitButton.disabled = false;
                                showError('Authentication timed out. Please try again.');
                            }
                        }, 5 * 60 * 1000);
                        
                    } else if (data.error) {
                        showError(`Authentication error: ${data.error}`);
                        submitButton.textContent = originalText;
                        submitButton.disabled = false;
                    }
                } catch (error) {
                    console.error('Error during authentication:', error);
                    showError(`Authentication error: ${error.message}`);
                    const submitButton = addAccountForm.querySelector('.submit-button');
                    submitButton.textContent = 'Add Account';
                    submitButton.disabled = false;
                }
            } else {
                // For offline Bedrock accounts, just save the username
                const username = bedrockAccountUsername.value.trim();
                if (!username) {
                    showError('Please enter a Bedrock username');
                    return;
                }
                
                // Create new account - use username as the name
                const newAccount = {
                    id: Date.now().toString(),
                    type: 'bedrock',
                    username: username,
                    authenticated: false,
                    createdAt: Date.now()
                };
                
                accounts.push(newAccount);
                saveAccounts();
                updateAccountSelector();
                
                // Select the new account
                accountSelector.value = newAccount.id;
                accountSelector.dispatchEvent(new Event('change'));
                
                // Hide modal
                accountModal.style.display = 'none';
                showToast(`Bedrock account "${username}" added successfully`, 'success');
            }
        } else {
            // For Java accounts, we need to authenticate with Microsoft/Xbox
            try {
                // Show loading state
                const submitButton = addAccountForm.querySelector('.submit-button');
                const originalText = submitButton.textContent;
                submitButton.textContent = 'Authenticating...';
                submitButton.disabled = true;
                
                // Request Microsoft authentication
                const response = await fetch('/api/minecraft/request-auth', {
                    method: 'POST'
                });
                
                const data = await response.json();
                
                if (data.status === 'auth_required' && data.authUrl) {
                    // Open the auth URL in a new window
                    window.open(data.authUrl, '_blank');
                    
                    // Show instructions to the user
                    showToast('Please complete authentication in the opened browser window', 'info', 10000);
                    
                    // Start polling for auth completion
                    let authCheckInterval = setInterval(async () => {
                        try {
                            const checkResponse = await fetch('/api/minecraft/check-auth');
                            const checkData = await checkResponse.json();
                            
                            if (checkData.status === 'authenticated') {
                                clearInterval(authCheckInterval);
                                
                                // Create new account with Xbox profile info and email if available
                                const newAccount = {
                                    id: Date.now().toString(),
                                    type: 'java',
                                    xboxUsername: checkData.username || 'Xbox User',
                                    email: checkData.email, // Store email if available
                                    createdAt: Date.now(),
                                    lastAuthenticated: Date.now()
                                };
                                
                                accounts.push(newAccount);
                                saveAccounts();
                                updateAccountSelector();
                                
                                // Select the new account
                                accountSelector.value = newAccount.id;
                                accountSelector.dispatchEvent(new Event('change'));
                                
                                // Hide modal
                                accountModal.style.display = 'none';
                                
                                // Use email or username in the success message
                                const displayName = checkData.email || checkData.username || 'Xbox User';
                                showToast(`Java account "${displayName}" added successfully`, 'success');
                                
                                // Reset form state
                                submitButton.textContent = originalText;
                                submitButton.disabled = false;
                            } else if (checkData.status === 'error') { // <--- Error detected here
                                clearInterval(authCheckInterval);
                                // Calls showError, which displays the toast
                                showError(`Authentication failed: ${checkData.error}`); 
                                submitButton.textContent = originalText;
                                submitButton.disabled = false;
                            }
                            // Continue polling if not authenticated yet
                        } catch (error) {
                            console.error('Error checking auth status:', error);
                        }
                    }, 2000);
                    
                    // Set a timeout to stop polling after 5 minutes
                    setTimeout(() => {
                        if (authCheckInterval) {
                            clearInterval(authCheckInterval);
                            submitButton.textContent = originalText;
                            submitButton.disabled = false;
                            showError('Authentication timed out. Please try again.');
                        }
                    }, 5 * 60 * 1000);
                    
                } else if (data.error) {
                    showError(`Authentication error: ${data.error}`);
                    submitButton.textContent = originalText;
                    submitButton.disabled = false;
                }
            } catch (error) {
                console.error('Error during authentication:', error);
                showError(`Authentication error: ${error.message}`);
                const submitButton = addAccountForm.querySelector('.submit-button');
                submitButton.textContent = 'Add Account';
                submitButton.disabled = false;
            }
        }
    });
    
    // Update connect button text initially
    updateConnectButtonText();
}

// Helper function to update connect button text based on selected account
function updateConnectButtonText() {
    if (selectedAccount) {
        if (selectedAccount.type === 'bedrock') {
            connectButton.textContent = `Connect as ${selectedAccount.username}`;
        } else {
            // For Java accounts, prefer email if available
            const displayName = selectedAccount.email || selectedAccount.xboxUsername || 'Xbox User';
            connectButton.textContent = `Connect as ${displayName}`;
        }
    } else {
        // Default text based on edition
        if (currentEdition === 'bedrock') {
            connectButton.textContent = 'Connect with Bedrock Account';
        } else {
            connectButton.textContent = 'Connect with Microsoft Account';
        }
    }
}

function handleEditionChange(event) {
    currentEdition = event.target.value;
    
    // Show/hide edition-specific fields
    if (currentEdition === 'bedrock') {
        document.getElementById('bedrock-fields').classList.remove('hidden');
        document.getElementById('java-fields').classList.add('hidden');
        
        // Set port to Bedrock default (19132)
        serverPortInput.value = '19132';
    } else {
        document.getElementById('bedrock-fields').classList.add('hidden');
        document.getElementById('java-fields').classList.remove('hidden');
        
        // Set port to Java default (25565)
        serverPortInput.value = '25565';
    }
    
    // Update connect button text
    updateConnectButtonText();
}


// Function to update connection info
function updateConnectionInfo(data) {
    document.getElementById('info-username').textContent = data.username || 'Unknown';
    document.getElementById('info-server').textContent = `${data.serverAddress}:${data.serverPort}`;
    document.getElementById('info-edition').textContent = data.edition || 'Java';
    
    // Update uptime
    if (data.startTime) {
        // Clear any existing uptime intervals first
        clearUptimeIntervals();
        
        const updateUptime = () => {
            const uptime = Math.floor((Date.now() - data.startTime) / 1000);
            const hours = Math.floor(uptime / 3600);
            const minutes = Math.floor((uptime % 3600) / 60);
            const seconds = uptime % 60;
            document.getElementById('info-uptime').textContent = 
                `${hours}h ${minutes}m ${seconds}s`;
        };
        
        updateUptime();
        const intervalId = setInterval(updateUptime, 1000);
        
        // Store the interval ID for cleanup
        uptimeIntervals.push(intervalId);
    }
}

// Function to clear uptime intervals
function clearUptimeIntervals() {
    uptimeIntervals.forEach(interval => clearInterval(interval));
    uptimeIntervals = [];
}

// Toast and UI helper functions
function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    toast.textContent = message; // <--- Sets the text content
    toast.className = `toast ${type} show`; // <--- Applies styling and makes it visible
    
    setTimeout(() => {
        toast.className = toast.className.replace('show', '');
    }, 3000);
}

function setLoading(element, isLoading) {
    if (isLoading) {
        element.classList.add('loading');
        element.disabled = true;
    } else {
        element.classList.remove('loading');
        element.disabled = false;
    }
}

function showError(message) {
    showToast(message, 'error');
}

// Function to update UI for connected state
function showConnectedState() {
    statusElement.textContent = 'Status: Connected';
    statusElement.className = 'status connected';
    connectionInfoElement.style.display = 'block';
    disconnectContainer.style.display = 'block';
    chatContainer.style.display = 'block';
    document.getElementById('connection-form').style.display = 'none';
    
    // Save connection to storage
    if (currentConnectionId) {
        saveConnectionToStorage(currentConnectionId);
    }
}

// Function to update UI for disconnected state
function showDisconnectedState() {
    statusElement.textContent = 'Status: Disconnected';
    statusElement.className = 'status disconnected';
    connectionInfoElement.style.display = 'none';
    disconnectContainer.style.display = 'none';
    chatContainer.style.display = 'none';
    document.getElementById('connection-form').style.display = 'block';
    
    // Reset uptime display to 0
    const uptimeElement = document.getElementById('info-uptime');
    if (uptimeElement) {
        uptimeElement.textContent = '0h 0m 0s';
    }
    
    // Clear connection from storage
    clearConnectionFromStorage();
    
    // Clear intervals
    if (statusCheckInterval) {
        clearInterval(statusCheckInterval);
        statusCheckInterval = null;
    }
    
    if (chatCheckInterval) {
        clearInterval(chatCheckInterval);
        chatCheckInterval = null;
    }
    
    // Clear uptime intervals
    clearUptimeIntervals();
    
    // Reset connection ID
    currentConnectionId = null;
}

// Storage functions
function saveConnectionToStorage(connectionId) {
    try {
        localStorage.setItem('minecraft_afk_connection', connectionId);
    } catch (e) {
        console.error('Failed to save connection to storage:', e);
    }
}

function getConnectionFromStorage() {
    try {
        return localStorage.getItem('minecraft_afk_connection');
    } catch (e) {
        console.error('Failed to get connection from storage:', e);
        return null;
    }
}

function clearConnectionFromStorage() {
    try {
        localStorage.removeItem('minecraft_afk_connection');
    } catch (e) {
        console.error('Failed to clear connection from storage:', e);
    }
}

// Function to disconnect from the server
async function disconnectFromServer() {
    if (!currentConnectionId) {
        showToast('No active connection to disconnect from');
        return;
    }
    
    try {
        setLoading(disconnectButton, true);
        
        // First, reset any auth state
        await fetch('/api/minecraft/reset-auth', {
            method: 'POST'
        });
        
        // Then disconnect
        const response = await fetch(`/api/minecraft/disconnect/${currentConnectionId}`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast('Successfully disconnected from the server');
            showDisconnectedState();
        } else {
            showError(`Failed to disconnect: ${data.error}`);
        }
    } catch (error) {
        showError(`Error: ${error.message}`);
    } finally {
        setLoading(disconnectButton, false);
    }
}

// Reconnection functionality
async function attemptReconnect() {
    if (reconnectAttempts >= maxReconnectAttempts) {
        showError(`Failed to reconnect after ${maxReconnectAttempts} attempts`);
        showDisconnectedState();
        return;
    }
    
    reconnectAttempts++;
    
    try {
        statusElement.textContent = `Status: Reconnecting (Attempt ${reconnectAttempts}/${maxReconnectAttempts})...`;
        
        // Reset uptime display to 0
        const uptimeElement = document.getElementById('info-uptime');
        if (uptimeElement) {
            uptimeElement.textContent = '0h 0m 0s';
        }
        
        // Get the last known server details
        const serverAddress = document.getElementById('info-server').textContent.split(':')[0];
        const serverPort = document.getElementById('info-server').textContent.split(':')[1];
        
        if (!serverAddress) {
            throw new Error('No server address available for reconnection');
        }
        
        // Reset auth state before reconnecting
        await fetch('/api/minecraft/reset-auth', {
            method: 'POST'
        });
        
        const response = await fetch('/api/minecraft/connect-mineflayer', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                serverAddress,
                serverPort
            })
        });
        
        const data = await response.json();
        
        if (data.error) {
            throw new Error(data.error);
        }
        
        if (data.status === 'connected') {
            currentConnectionId = data.connectionId;
            
            // Update UI
            showConnectedState();
            showToast('Successfully reconnected to server!', 'success');
            
            // Reset reconnect attempts
            reconnectAttempts = 0;
            
            // Start checking status
            statusCheckInterval = setInterval(checkConnectionStatus, 5000);
            
            // Start checking chat messages
            chatCheckInterval = setInterval(fetchChatMessages, 2000);
            
            // Update connection info
            updateConnectionInfo({
                username: data.username,
                serverAddress,
                serverPort,
                startTime: Date.now()
            });
        }
    } catch (error) {
        console.error('Reconnection error:', error);
        
        // Try again after a delay
        reconnectTimeout = setTimeout(attemptReconnect, 5000);
    }
}

// Connection check functions
async function checkConnectionStatus() {
    if (!currentConnectionId) return;
    
    try {
        const response = await fetch(`/api/minecraft/status/${currentConnectionId}`);
        const data = await response.json();
        
        if (data.status === 'disconnected') {
            // Try to reconnect
            showToast('Connection lost. Attempting to reconnect...', 'error');
            
            // Clear existing intervals
            if (statusCheckInterval) {
                clearInterval(statusCheckInterval);
                statusCheckInterval = null;
            }
            
            if (chatCheckInterval) {
                clearInterval(chatCheckInterval);
                chatCheckInterval = null;
            }
            
            // Clear uptime intervals
            clearUptimeIntervals();
            
            // Start reconnection process
            reconnectAttempts = 0;
            attemptReconnect();
        } else {
            // Update connection info
            updateConnectionInfo(data);
        }
    } catch (error) {
        console.error('Error checking status:', error);
    }
}

// Check for active connections on page load
async function checkForActiveConnections() {
    try {
        // First check local storage
        const savedConnectionId = getConnectionFromStorage();
        
        if (savedConnectionId) {
            console.log('Found saved connection ID:', savedConnectionId);
            
            // Try to verify this connection is still active
            const statusResponse = await fetch(`/api/minecraft/status/${savedConnectionId}`);
            const statusData = await statusResponse.json();
            
            console.log('Connection status:', statusData);
            
            if (statusData.status === 'connected') {
                // Connection is still active
                currentConnectionId = savedConnectionId;
                
                // Update UI
                showConnectedState();
                
                // Start checking status
                statusCheckInterval = setInterval(checkConnectionStatus, 5000);
                
                // Start checking chat messages
                chatCheckInterval = setInterval(fetchChatMessages, 2000);
                
                // Update connection info
                updateConnectionInfo({
                    username: statusData.username,
                    serverAddress: statusData.serverAddress,
                    serverPort: statusData.serverPort,
                    startTime: statusData.startTime
                });
            } else {
                showDisconnectedState();
            }
        } else {
            showDisconnectedState();
        }
    } catch (error) {
        console.error('Error checking for active connections:', error);
        showDisconnectedState();
    }
}

// Function to fetch chat messages
async function fetchChatMessages() {
    if (!currentConnectionId) return;
    
    try {
        const response = await fetch(`/api/minecraft/chat/${currentConnectionId}`);
        const data = await response.json();
        
        // Clear existing messages
        chatMessages.innerHTML = '';
        
        // Add messages
        data.messages.forEach(msg => {
            const messageElement = document.createElement('div');
            messageElement.className = 'chat-message';
            messageElement.textContent = msg.message;
            chatMessages.appendChild(messageElement);
        });
        
        // Scroll to bottom
        chatMessages.scrollTop = chatMessages.scrollHeight;
    } catch (error) {
        console.error('Error fetching chat messages:', error);
    }
}

// Function to reset auth state
async function resetAuthState() {
    try {
        await fetch('/api/minecraft/reset-auth', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        console.log('Auth state reset');
    } catch (error) {
        console.error('Error resetting auth state:', error);
    }
}

async function connectToServer(event) {
    event.preventDefault();
    
    // Reset any existing connection state first
    if (currentConnectionId) {
        await disconnectFromServer();
    }
    
    // Clear any lingering intervals
    if (statusCheckInterval) {
        clearInterval(statusCheckInterval);
        statusCheckInterval = null;
    }
    
    // Clear uptime intervals
    clearUptimeIntervals();
    
    // Reset uptime display to 0
    const uptimeElement = document.getElementById('info-uptime');
    if (uptimeElement) {
        uptimeElement.textContent = '0h 0m 0s';
    }
    
    // Reset auth state
    try {
        await fetch('/api/minecraft/reset-auth', {
            method: 'POST'
        });
    } catch (e) {
        console.error('Failed to reset auth state:', e);
    }
    
    // Now proceed with connection
    const serverAddress = serverAddressInput.value.trim();
    const serverPort = serverPortInput.value.trim() || (currentEdition === 'java' ? '25565' : '19132');
    
    if (!serverAddress) {
        return showError('Please enter a server address');
    }
    
    try {
        statusElement.textContent = 'Status: Connecting...';
        setLoading(connectButton, true);
        
        // Choose the appropriate endpoint based on edition
        const endpoint = currentEdition === 'java' 
            ? '/api/minecraft/connect-mineflayer'
            : '/api/minecraft/connect-bedrock';
        
        const requestBody = {
            serverAddress,
            serverPort
        };
        
        // Add account ID if an account is selected
        if (selectedAccount) {
            requestBody.accountId = selectedAccount.id;
            
            // For Bedrock, also include the username
            if (currentEdition === 'bedrock') {
                requestBody.username = selectedAccount.username;
                requestBody.useSelectedAccount = true;
            }
        }
        
        console.log('Sending connection request:', JSON.stringify(requestBody));
        
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestBody)
        });
        
        const data = await response.json();
        
        if (data.error) {
            showError(data.error);
            statusElement.textContent = 'Status: Connection Failed';
            return;
        }
        
        if (data.status === 'connected' || data.status === 'connecting') {
            currentConnectionId = data.connectionId;
            
            // Update UI
            showConnectedState();
            showToast('Successfully connected to server!', 'success');
            
            // Start checking status
            statusCheckInterval = setInterval(checkConnectionStatus, 5000);
            
            // Start checking chat messages
            chatCheckInterval = setInterval(fetchChatMessages, 2000);
            
            // Update connection info
            updateConnectionInfo({
                username: data.username || (selectedAccount ? selectedAccount.username : 'Unknown'),
                serverAddress,
                serverPort,
                edition: currentEdition === 'java' ? 'Java Edition' : 'Bedrock Edition',
                startTime: Date.now()
            });
        } else if (data.status === 'auth_required') {
            // Handle authentication flow if needed
            showToast('Authentication required. Please complete the authentication in the opened browser window.', 'info');
            
            // If an auth URL was provided, open it
            if (data.authUrl) {
                window.open(data.authUrl, '_blank');
            }
        }
    } catch (error) {
        showError(error.message);
        statusElement.textContent = 'Status: Connection Failed';
    } finally {
        setLoading(connectButton, false);
    }
}

// Update the initConnectButton function
function initConnectButton() {
    // Remove any existing event listeners
    const newButton = connectButton.cloneNode(true);
    connectButton.parentNode.replaceChild(newButton, connectButton);
    connectButton = newButton;
    
    // Add the event listener
    connectButton.addEventListener('click', connectToServer);
    
    // Set the initial button text based on the selected edition
    if (currentEdition === 'bedrock') {
        connectButton.textContent = 'Connect with Bedrock Account';
    } else {
        connectButton.textContent = 'Connect with Microsoft Account';
    }
}

// Function to send message
async function sendMessage() {
    if (!currentConnectionId) return;
    
    const message = chatInput.value.trim();
    if (!message) return;
    
    try {
        const response = await fetch(`/api/minecraft/send-message/${currentConnectionId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ message })
        });
        
        const data = await response.json();
        
        if (data.error) {
            showError(data.error);
            return;
        }
        
        // Clear input
        chatInput.value = '';
        
        // Fetch latest messages
        fetchChatMessages();
    } catch (error) {
        showError(error.message);
    }
}

// Initialize the application
function initApp() {
    // Initialize DOM references
    initDomReferences();

    // Initialize account management
    initAccountManagement();
    
    // Event listeners
    disconnectButton.addEventListener('click', async function() {
        if (!currentConnectionId) return;
        
        try {
            statusElement.textContent = 'Status: Disconnecting...';
            setLoading(this, true);
            
            await disconnectFromServer();
            
            // Reset auth state and reinitialize connect button
            await resetAuthState();
            initConnectButton();
            
        } catch (error) {
            showError(error.message);
        } finally {
            setLoading(this, false);
        }
    });
    
    // Add event listener for send message button
    sendMessageButton.addEventListener('click', sendMessage);
    
    // Add event listener for enter key in chat input
    chatInput.addEventListener('keypress', function(event) {
        if (event.key === 'Enter') {
            sendMessage();
        }
    });
    
    // Initialize the connect button
    initConnectButton();
    
    // Initialize UI by checking for active connections
    checkForActiveConnections();
}

// Run initialization when DOM is fully loaded
document.addEventListener('DOMContentLoaded', function() {
    initApp();
    console.log('DOMContentLoaded event fired');
});