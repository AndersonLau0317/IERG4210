async function getCsrfToken() {
    const response = await fetch('/api/csrf-token');
    const data = await response.json();
    return data.token;
}

document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const email = formData.get('email');
    const password = formData.get('password');

    try {
        // Get CSRF token
        const csrfToken = await getCsrfToken();

        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ email, password })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Login failed');
        }

        const data = await response.json();
        if (data.is_admin) {
            window.location.href = '/admin/panel';
        } else {
            window.location.href = '/';
        }
    } catch (err) {
        document.getElementById('error-message').textContent = err.message;
        document.getElementById('error-message').style.display = 'block';
    }
});
