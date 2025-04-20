// Check if the user is already authenticated
function checkAuthentication() {
    const isAuthenticated = localStorage.getItem('mc_afk_auth');
    
    if (!isAuthenticated) {
        // Show the password overlay
        document.getElementById('password-overlay').style.display = 'flex';
    } else {
        // Hide the password overlay
        document.getElementById('password-overlay').style.display = 'none';
        // Show the main content
        document.getElementById('main-content').style.display = 'block';
    }
}

// Function to verify the password
async function verifyPassword() {
    const passwordInput = document.getElementById('password-input');
    const password = passwordInput.value.trim();
    const errorMessage = document.getElementById('password-error');
    
    if (!password) {
        errorMessage.textContent = 'Please enter the password';
        return;
    }
    
    try {
        const response = await fetch('/verify-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            // Store authentication in localStorage
            localStorage.setItem('mc_afk_auth', 'true');
            // Hide the password overlay
            document.getElementById('password-overlay').style.display = 'none';
            // Show the main content
            document.getElementById('main-content').style.display = 'block';
        } else {
            errorMessage.textContent = 'Invalid password. Please try again.';
            passwordInput.value = '';
        }
    } catch (error) {
        console.error('Error verifying password:', error);
        errorMessage.textContent = 'An error occurred. Please try again.';
    }
}

// Add event listener for the password form
document.addEventListener('DOMContentLoaded', () => {
    checkAuthentication();
    
    const passwordForm = document.getElementById('password-form');
    passwordForm.addEventListener('submit', (e) => {
        e.preventDefault();
        verifyPassword();
    });
    
    // Add event listener for Enter key in password input
    const passwordInput = document.getElementById('password-input');
    passwordInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            verifyPassword();
        }
    });
});