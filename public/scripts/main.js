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
                this.updateQuantity(item.pid, item.quantity - 1);
            li.querySelector('input').onchange = (e) => 
                this.updateQuantity(item.pid, parseInt(e.target.value));
            li.querySelector('.remove-item').onclick = () => 
                this.removeItem(item.pid);

            list.appendChild(li);
        }

        // Fix total calculation by removing extra parentheses
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
    const currentCategory = urlParams.get("category");
    
    try {
        let catid;
        if (currentCategory === 'category1') catid = 1;
        else if (currentCategory === 'category2') catid = 2;
        
        const response = await fetch(`/api/products${catid ? `?catid=${catid}` : ''}`);
        if (!response.ok) throw new Error('Failed to fetch products');
        
        const products = await response.json();
        
        const productList = document.querySelector(".product-list");
        if (products.length === 0) {
            productList.innerHTML = '<p>No products found in this category.</p>';
            return;
        }
        
        productList.innerHTML = products.map(product => `
            <div class="product">
                <a href="product.html?id=${product.pid}">
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
        document.querySelector(".product-list").innerHTML = 
            '<p>Error loading products. Please try again later.</p>';
    }
}

// Load products and shopping cart when the page loads
window.addEventListener('DOMContentLoaded', () => {
    loadProducts();
    cart.restoreFromStorage();
});