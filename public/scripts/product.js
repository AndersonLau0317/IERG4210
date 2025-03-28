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

    // ...existing cart methods from main.js...
}

// Initialize cart
const cart = new ShoppingCart();

// Load product details
async function loadProductDetails() {
    const urlParams = new URLSearchParams(window.location.search);
    const pid = parseInt(urlParams.get('id'));
    const catid = parseInt(urlParams.get('catid'));

    try {
        // Fetch product details
        const response = await fetch(`/api/products/${pid}`);
        if (!response.ok) throw new Error('Failed to fetch product');
        const product = await response.json();

        // Fetch category details
        const catResponse = await fetch('/api/categories');
        const categories = await catResponse.json();
        const category = categories.find(c => c.catid === catid);

        // Update breadcrumb
        const breadcrumb = document.querySelector('.breadcrumb ul');
        breadcrumb.innerHTML = `
            <li><a href="index.html">Home</a></li>
            <li><a href="category.html?catid=${catid}">${category?.name || 'Category'}</a></li>
            <li><span>${product.name}</span></li>
        `;

        // Update product details
        const productDetails = document.querySelector('.product-details');
        productDetails.innerHTML = `
            <img src="/images/products/${product.image_original}" alt="${product.name}">
            <h1>${product.name}</h1>
            <p>${product.description}</p>
            <p>$${product.price.toFixed(2)}</p>
            <button class="add-to-cart" data-pid="${product.pid}">Add to Cart</button>
        `;

        // Add event listener to Add to Cart button
        document.querySelector('.add-to-cart').addEventListener('click', async () => {
            await cart.addItem(product.pid);
        });

    } catch (err) {
        console.error('Error loading product:', err);
        document.querySelector('.product-details').innerHTML = 
            '<p>Error loading product details. Please try again later.</p>';
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    loadProductDetails();
    cart.restoreFromStorage();
});