class CartItem {
    constructor(pid, quantity = 1) {
        this.pid = pid;
        this.quantity = quantity;
        this.price = 0;
        this.name = '';
    }

    async fetchDetails() {
        const response = await fetch(`/api/products/${this.pid}`);
        if (!response.ok) throw new Error('Failed to fetch product details');
        const product = await response.json();
        this.name = product.name;
        this.price = product.price;
        return this;
    }
}

class ShoppingCart {
    constructor() {
        this.items = new Map();
        this.restoreFromStorage();
    }

    async addItem(pid) {
        if (!this.items.has(pid)) {
            const item = new CartItem(pid);
            await item.fetchDetails();
            this.items.set(pid, item);
        } else {
            // Increment quantity if item already exists
            const item = this.items.get(pid);
            item.quantity += 1;
        }
        this.saveToStorage();
        this.render();
    }

    updateQuantity(pid, quantity) {
        const item = this.items.get(pid);
        if (item) {
            item.quantity = Math.max(1, quantity);
            this.saveToStorage();
            this.render();
        }
    }

    removeItem(pid) {
        this.items.delete(pid);
        this.saveToStorage();
        this.render();
    }

    calculateTotal() {
        let total = 0;
        for (const item of this.items.values()) {
            total += item.price * item.quantity;
        }
        return total;
    }

    saveToStorage() {
        const data = Array.from(this.items.values()).map(item => ({
            pid: item.pid,
            quantity: item.quantity,
            price: item.price,
            name: item.name
        }));
        localStorage.setItem('shoppingCart', JSON.stringify(data));
    }

    async restoreFromStorage() {
        const data = localStorage.getItem('shoppingCart');
        if (data) {
            const items = JSON.parse(data);
            this.items.clear();
            for (const item of items) {
                const cartItem = new CartItem(item.pid, item.quantity);
                cartItem.price = item.price;
                cartItem.name = item.name;
                this.items.set(item.pid, cartItem);
            }
            this.render();
        }
    }

    render() {
        const list = document.getElementById('shopping-list-items');
        if (!list) return; // Prevent error on pages without cart
        list.innerHTML = '';

        for (const item of this.items.values()) {
            const li = document.createElement('li');
            li.innerHTML = `
                <span>${item.name}</span>
                <div class="quantity-controls">
                    <button class="decrement">-</button>
                    <input type="number" value="${item.quantity}" min="1">
                    <button class="increment">+</button>
                </div>
                <span>$${(item.price * item.quantity).toFixed(2)}</span>
                <button class="remove-item">Remove</button>
            `;

            // Fix event listener bindings
            li.querySelector('.increment').onclick = () =>
                this.updateQuantity(item.pid, item.quantity + 1);
            li.querySelector('.decrement').onclick = () =>
                this.updateQuantity(item.pid, Math.max(1, item.quantity - 1));
            li.querySelector('input').onchange = (e) =>
                this.updateQuantity(item.pid, Math.max(1, parseInt(e.target.value) || 1));
            li.querySelector('.remove-item').onclick = () =>
                this.removeItem(item.pid);

            list.appendChild(li);
        }

        // Show total
        const total = document.createElement('li');
        total.className = 'cart-total';
        total.innerHTML = `<strong>Total: $${this.calculateTotal().toFixed(2)}</strong>`;
        list.appendChild(total);
    }
}

// Initialize shopping cart
const cart = new ShoppingCart();

// Load products from API and set up event listeners
async function loadProducts() {
    const urlParams = new URLSearchParams(window.location.search);
    const catid = urlParams.get("catid"); // Get catid directly instead of 'category'

    try {
        const response = await fetch(`/api/products${catid ? `?catid=${catid}` : ''}`);
        if (!response.ok) throw new Error('Failed to fetch products');

        const products = await response.json();

        const productList = document.querySelector(".product-list");
        if (!productList) return; // Prevent error on pages without product list

        if (products.length === 0) {
            productList.innerHTML = '<p>No products found in this category.</p>';
            return;
        }

        productList.innerHTML = products.map(product => `
            <div class="product">
                <a href="product.html?id=${product.pid}&catid=${product.catid}">
                    <img src="/images/products/${product.image_thumbnail || 'placeholder.jpg'}" alt="${product.name}">
                    <h3>${product.name}</h3>
                </a>
                <p>$${product.price.toFixed(2)}</p>
                <button class="add-to-cart" data-pid="${product.pid}">Add to Cart</button>
            </div>
        `).join('');

        // Add event listeners after products are loaded
        document.querySelectorAll('.add-to-cart').forEach(button => {
            button.addEventListener('click', async (e) => {
                e.preventDefault();
                const pid = parseInt(button.dataset.pid);
                await cart.addItem(pid);
            });
        });
    } catch (err) {
        console.error('Error loading products:', err);
        const productList = document.querySelector(".product-list");
        if (productList) {
            productList.innerHTML =
                '<p>Error loading products. Please try again later.</p>';
        }
    }
}

// Load categories and update navigation
async function loadCategoryNav() {
    try {
        const response = await fetch('/api/categories');
        const categories = await response.json();

        const navList = document.querySelector('nav:not(.breadcrumb) ul');
        if (!navList) return; // Prevent error on pages without nav
        navList.innerHTML = `
            <li><a href="index.html">Home</a></li>
            ${categories.map(cat =>
                `<li><a href="category.html?catid=${cat.catid}">${cat.name}</a></li>`
            ).join('')}
        `;

        // Update breadcrumb if on category page
        const urlParams = new URLSearchParams(window.location.search);
        const catid = urlParams.get('catid');
        if (catid) {
            const category = categories.find(c => c.catid === parseInt(catid));
            if (category) {
                const breadcrumb = document.querySelector('.breadcrumb ul');
                if (breadcrumb) {
                    breadcrumb.innerHTML = `
                        <li><a href="index.html">Home</a></li>
                        <li><span>${category.name}</span></li>
                    `;
                }
            }
        }
    } catch (err) {
        console.error('Error loading categories:', err);
    }
}

// Load products and shopping cart when the page loads
window.addEventListener('DOMContentLoaded', () => {
    loadCategoryNav();
    loadProducts();
    cart.restoreFromStorage();

    // Add checkout button handler
    const checkoutBtn = document.querySelector('.checkout');
    if (checkoutBtn) {
        checkoutBtn.addEventListener('click', (e) => {
            e.preventDefault();
            window.location.href = '/checkout.html';
        });
    }
});