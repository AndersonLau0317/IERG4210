async function getCsrfToken() {
    const response = await fetch('/api/csrf-token');
    const data = await response.json();
    return data.token;
}

async function checkAuthStatus() {
    try {
        const response = await fetch('/api/user');
        const user = await response.json();
        
        // Check if we're in admin panel
        const isAdminPage = window.location.pathname.includes('/admin/panel');
        
        const headerHtml = `
            <div class="auth-section">
                ${user.email !== 'guest' 
                    ? `<span class="user-email">${user.email}</span>
                       <button class="change-password-btn" onclick="showChangePasswordModal()">Change Password</button>
                       <button class="logout-btn" onclick="logout()">Logout</button>
                       ${user.is_admin 
                           ? `<a href="${isAdminPage ? '/' : '/admin/panel'}" class="admin-link">
                                ${isAdminPage ? 'Home Page' : 'Admin Panel'}
                              </a>`
                           : ''}`
                    : '<a href="/admin/login" class="login-link">Login</a>'}
            </div>
            
            <!-- Change Password Modal -->
            <div id="change-password-modal" class="modal">
                <div class="modal-content">
                    <h2>Change Password</h2>
                    <div id="password-error" class="error-message"></div>
                    <form id="change-password-form">
                        <div>
                            <label for="currentPassword">Current Password:</label>
                            <input type="password" id="currentPassword" required>
                        </div>
                        <div>
                            <label for="newPassword">New Password:</label>
                            <input type="password" id="newPassword" required>
                        </div>
                        <div>
                            <label for="confirmPassword">Confirm Password:</label>
                            <input type="password" id="confirmPassword" required>
                        </div>
                        <div class="modal-buttons">
                            <button type="submit">Change Password</button>
                            <button type="button" onclick="hideChangePasswordModal()">Cancel</button>
                        </div>
                    </form>
                </div>
            </div>`;
        
        document.querySelector('header').insertAdjacentHTML('beforeend', headerHtml);
        
        // Add event listener for change password form
        const changePasswordForm = document.getElementById('change-password-form');
        if (changePasswordForm) {
            changePasswordForm.addEventListener('submit', handleChangePassword);
        }
    } catch (err) {
        console.error('Error checking auth status:', err);
    }
}

function showChangePasswordModal() {
    const modal = document.getElementById('change-password-modal');
    modal.style.display = 'block';
}

function hideChangePasswordModal() {
    const modal = document.getElementById('change-password-modal');
    modal.style.display = 'none';
    document.getElementById('change-password-form').reset();
    document.getElementById('password-error').textContent = '';
}

async function handleChangePassword(e) {
    e.preventDefault();
    const errorElement = document.getElementById('password-error');
    
    const currentPassword = document.getElementById('currentPassword').value;
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    
    if (newPassword !== confirmPassword) {
        errorElement.textContent = 'New passwords do not match';
        return;
    }
    
    try {
        const csrfToken = await getCsrfToken();
        
        const response = await fetch('/api/change-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ currentPassword, newPassword })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to change password');
        }
        
        // Password changed successfully, redirect to login
        window.location.href = '/admin/login';
    } catch (err) {
        errorElement.textContent = err.message;
    }
}

async function logout() {
    try {
        // Get CSRF token first
        const csrfToken = await getCsrfToken();

        const response = await fetch('/api/logout', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            }
        });
        
        if (response.ok) {
            window.location.href = '/';
        } else {
            console.error('Logout failed');
        }
    } catch (err) {
        console.error('Error during logout:', err);
    }
}

// Initialize auth status when page loads
document.addEventListener('DOMContentLoaded', checkAuthStatus);