async function getCsrfToken() {
    const response = await fetch('/api/csrf-token');
    const data = await response.json();
    return data.token;
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
            window.location.href = '/admin/login';
        } else {
            throw new Error('Logout failed');
        }
    } catch (err) {
        console.error('Error during logout:', err);
        alert('Logout failed. Please try again.');
    }
}

// Add session check function
async function validateAdminSession() {
    try {
        const response = await fetch('/api/user');
        const user = await response.json();
        
        if (!user.is_admin) {
            window.location.replace('/admin/login');
            return false;
        }
        return true;
    } catch (err) {
        window.location.replace('/admin/login');
        return false;
    }
}

// Add periodic check
let sessionCheckInterval;

document.addEventListener('DOMContentLoaded', async () => {
    // Initial check
    if (!await validateAdminSession()) return;

    // Set up periodic checks
    sessionCheckInterval = setInterval(validateAdminSession, 30000); // Check every 30 seconds

    // Clear interval when leaving page
    window.addEventListener('beforeunload', () => {
        clearInterval(sessionCheckInterval);
    });

    // Initialize admin features
    loadCategories();
    loadProducts();
    loadOrders(); // Load orders on initial page load

    // Category form submission
    document.getElementById('category-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const name = formData.get('name');
        
        try {
            const csrfToken = await getCsrfToken();
            const response = await fetch('/api/categories', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                },
                body: JSON.stringify({ name })
            });
            if (!response.ok) throw new Error('Failed to add category');
            loadCategories();
            e.target.reset();
        } catch (err) {
            console.error(err);
            alert('Error adding category');
        }
    });

    // Product form submission
    document.getElementById('product-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        console.log('Product Form Data:', formData); // Add this line

        const imageInput = document.getElementById('product-image');
        if (imageInput.files.length === 0) {
            alert('Please select an image file.');
            return;
        }
        
        try {
            const csrfToken = await getCsrfToken();
            const response = await fetch('/api/products', {
                method: 'POST',
                headers: {
                    'X-CSRF-Token': csrfToken
                },
                body: formData
            });
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Failed to add product: ${response.status} ${response.statusText} - ${errorText}`);
            }
            loadProducts();
            e.target.reset();
        } catch (err) {
            console.error(err);
            alert(`Error adding product: ${err.message}`);
        }
    });
});

// Update visibility state handling
document.addEventListener('visibilitychange', async () => {
    if (document.visibilityState === 'visible') {
        // Revalidate session when tab becomes visible
        if (!await validateAdminSession()) return;
    }
});

async function loadCategories() {
    try {
        const response = await fetch('/api/categories');
        const categories = await response.json();
        
        // Update categories dropdown in product form
        const select = document.getElementById('product-category');
        select.innerHTML = categories.map(cat => 
            `<option value="${cat.catid}">${cat.name}</option>`
        ).join('');
        
        // Update categories list
        const list = document.getElementById('categories-list');
        list.innerHTML = categories.map(cat =>
            `<div class="category-item">
                <span>${cat.name}</span>
                <button onclick="deleteCategory(${cat.catid})">Delete</button>
            </div>`
        ).join('');
    } catch (err) {
        console.error(err);
    }
}

async function loadProducts() {
    try {
        const response = await fetch('/api/products');
        const products = await response.json();
        
        const list = document.getElementById('products-list');
        list.innerHTML = products.map(prod =>
            `<div class="product-item">
                <img src="/images/products/${prod.image_thumbnail}" alt="${prod.name}">
                <span>${prod.name} - $${prod.price}</span>
                <button onclick="deleteProduct(${prod.pid})">Delete</button>
            </div>`
        ).join('');
    } catch (err) {
        console.error(err);
    }
}

async function loadOrders() {
    try {
        const response = await fetch('/api/orders');
        const orders = await response.json();
        const list = document.getElementById('orders-list');
        list.innerHTML = orders.map(order => `
            <div class="order-item">
                <h3>Order ID: ${order.orderid}</h3>
                <p>Status: ${order.status}</p>
                <p>Total: $${order.total}</p>
                <p>Created: ${new Date(order.created_at).toLocaleString()}</p>
                <ul>
                    ${order.items && order.items.length > 0 ? order.items.map(item => `
                        <li>
                            ${item.name} &times; ${item.quantity} — $${(item.price * item.quantity).toFixed(2)}
                        </li>
                    `).join('') : '<li>No items</li>'}
                </ul>
            </div>
        `).join('');
    } catch (err) {
        console.error('Error loading orders:', err);
    }
}

async function deleteCategory(catid) {
    if (!confirm('Are you sure you want to delete this category and all its products?')) return;
    
    try {
        const csrfToken = await getCsrfToken();
        const response = await fetch(`/api/categories/${catid}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            }
        });
        
        if (!response.ok) throw new Error('Failed to delete category');
        
        await loadCategories();
        await loadProducts();
    } catch (err) {
        console.error('Delete category error:', err);
        alert(err.message || 'Error deleting category');
    }
}

async function deleteProduct(pid) {
    if (!confirm('Are you sure you want to delete this product?')) return;
    
    try {
        const csrfToken = await getCsrfToken();
        const response = await fetch(`/api/products/${pid}`, {
            method: 'DELETE',
            headers: {
                'X-CSRF-Token': csrfToken
            }
        });
        if (!response.ok) throw new Error('Failed to delete product');
        loadProducts();
    } catch (err) {
        console.error(err);
        alert('Error deleting product');
    }
}
