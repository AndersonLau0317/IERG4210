async function getCsrfToken() {
    const response = await fetch('/api/csrf-token');
    const data = await response.json();
    return data.token;
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('error-message').textContent = '';
    document.getElementById('error-message').style.display = 'none';
});

document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const email = formData.get('email');
    const password = formData.get('password');

    // Hide error message before attempting login
    const errorDiv = document.getElementById('error-message');
    errorDiv.textContent = '';
    errorDiv.style.display = 'none';

    try {
        // Get CSRF token
        const csrfToken = await getCsrfToken();
        console.log('CSRF Token:', csrfToken); // Debug log

        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken  // Make sure header name matches
            },
            credentials: 'include', // Important for cookies
            body: JSON.stringify({ email, password })
        });

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || 'Login failed');
        }

        // Store the CSRF token
        localStorage.setItem('csrfToken', data.csrfToken);

        if (data.is_admin) {
            window.location.href = '/admin/panel';
        } else {
            window.location.href = '/';
        }
    } catch (err) {
        errorDiv.textContent = err.message;
        errorDiv.style.display = 'block';
    }
});
