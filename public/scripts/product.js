class ProductPage {
    constructor() {
        console.log('ProductPage constructor called');

        this.product = null;
        this.category = null;

        // Load product details immediately
        this.loadProductDetails();
    }

    showLoading() {
        document.getElementById('product-img').src = '';
        document.getElementById('product-name').textContent = 'Loading...';
        document.getElementById('product-description').textContent = 'Loading...';
        document.getElementById('product-price').textContent = '$0.00';
    }

    showError(message) {
        document.getElementById('product-name').textContent = 'Error';
        document.getElementById('product-description').textContent = message;
        document.getElementById('product-price').textContent = '';
        document.getElementById('product-img').src = '';
    }

    updateBreadcrumb() {
        const breadcrumb = document.querySelector('.breadcrumb ul');
        if (breadcrumb && this.category) {
            breadcrumb.innerHTML = `
                <li><a href="index.html">Home</a></li>
                <li><a href="category.html?catid=${this.category.catid}">${this.category.name}</a></li>
                <li><span>${this.product.name}</span></li>
            `;
        }
    }

    updateProductDisplay() {
        const productImg = document.getElementById('product-img');
        const productName = document.getElementById('product-name');
        const productDescription = document.getElementById('product-description');
        const productPrice = document.getElementById('product-price');

        if (productImg) productImg.src = `/images/products/${this.product.image_original}`;
        if (productName) productName.textContent = this.product.name;
        if (productDescription) productDescription.textContent = this.product.description;
        if (productPrice) productPrice.textContent = `$${this.product.price.toFixed(2)}`;
    }

    async loadProductDetails() {
        console.log('Loading product details');

        const urlParams = new URLSearchParams(window.location.search);
        const pid = parseInt(urlParams.get('id'));
        const catid = parseInt(urlParams.get('catid'));

        console.log('Product ID:', pid);
        console.log('Category ID:', catid);

        if (!pid || !catid) {
            this.showError('Product ID and Category ID are required');
            return;
        }

        try {
            this.showLoading();

            // Fetch product details
            const productResponse = await fetch(`/api/products/${pid}`);
            if (!productResponse.ok) {
                throw new Error(`Failed to fetch product: ${productResponse.status}`);
            }
            this.product = await productResponse.json();

            // Fetch category details
            const categoriesResponse = await fetch('/api/categories');
            if (!categoriesResponse.ok) {
                throw new Error(`Failed to fetch categories: ${categoriesResponse.status}`);
            }
            const categories = await categoriesResponse.json();
            this.category = categories.find(c => c.catid === catid);

            if (!this.category) {
                throw new Error('Category not found');
            }

            // Update UI
            this.updateBreadcrumb();
            this.updateProductDisplay();

        } catch (error) {
            console.error('Error loading product:', error);
            this.showError(error.message || 'Failed to load product details');
        }
    }
}

// Make ProductPage available globally
ProductPage.initialize = function() {
    if (typeof window !== 'undefined') {
        window.ProductPage = this;
        console.log('ProductPage class registered globally');
    }
};

// Initialize the ProductPage class
ProductPage.initialize();