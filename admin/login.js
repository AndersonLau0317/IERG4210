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

document.getElementById('show-register-form').addEventListener('click', () => {
    document.querySelector('.login-form').style.display = 'none';
    document.querySelector('.register-form').style.display = 'block';
});

document.getElementById('show-login-form').addEventListener('click', () => {
    document.querySelector('.register-form').style.display = 'none';
    document.querySelector('.login-form').style.display = 'block';
});

document.getElementById('register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const email = formData.get('email');
    const password = formData.get('password');
    const confirmPassword = formData.get('confirmPassword');

    const errorDiv = document.getElementById('register-error-message');
    errorDiv.textContent = '';
    errorDiv.style.display = 'none';

    if (password !== confirmPassword) {
        errorDiv.textContent = 'Passwords do not match.';
        errorDiv.style.display = 'block';
        return;
    }

    try {
        const csrfToken = await getCsrfToken();
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ email, password })
        });

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || 'Registration failed');
        }

        alert('Registration successful! Please log in.');
        document.getElementById('show-login-form').click();
    } catch (err) {
        errorDiv.textContent = err.message;
        errorDiv.style.display = 'block';
    }
});
