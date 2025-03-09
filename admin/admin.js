document.addEventListener('DOMContentLoaded', () => {
    loadCategories();
    loadProducts();

    // Category form submission
    document.getElementById('category-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(e.target);
        const name = formData.get('name');
        
        try {
            const response = await fetch('/api/categories', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
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
        
        try {
            const response = await fetch('/api/products', {
                method: 'POST',
                body: formData
            });
            if (!response.ok) throw new Error('Failed to add product');
            loadProducts();
            e.target.reset();
        } catch (err) {
            console.error(err);
            alert('Error adding product');
        }
    });
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

async function deleteCategory(catid) {
    if (!confirm('Are you sure you want to delete this category and all its products?')) return;
    
    try {
        const response = await fetch(`/api/categories/${catid}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Failed to delete category');
        }
        
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
        const response = await fetch(`/api/products/${pid}`, {
            method: 'DELETE'
        });
        if (!response.ok) throw new Error('Failed to delete product');
        loadProducts();
    } catch (err) {
        console.error(err);
        alert('Error deleting product');
    }
}
