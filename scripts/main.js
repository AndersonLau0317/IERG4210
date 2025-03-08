// Load products from API
async function loadProducts() {
    const urlParams = new URLSearchParams(window.location.search);
    const currentCategory = urlParams.get("category");
    
    try {
        // Convert category1/category2 to actual category IDs
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
        
        // Add to Cart functionality
        document.querySelectorAll('.add-to-cart').forEach(button => {
            button.addEventListener('click', () => {
                const product = button.closest('.product');
                const productName = product.querySelector('h3').textContent;
                const productPrice = product.querySelector('p').textContent;

                const listItem = document.createElement('li');
                listItem.innerHTML = `
                <span>${productName}</span>
                <input type="number" value="1" min="1">
                <button class="remove-item">Remove</button>
                `;
                document.getElementById('shopping-list-items').appendChild(listItem);
                saveShoppingList();
            });
        });
    } catch (err) {
        console.error('Error loading products:', err);
        document.querySelector(".product-list").innerHTML = 
            '<p>Error loading products. Please try again later.</p>';
    }
}

// Load shopping list from localStorage
function loadShoppingList() {
    const shoppingList = JSON.parse(localStorage.getItem('shoppingList')) || [];
    const shoppingListItems = document.getElementById('shopping-list-items');
    shoppingListItems.innerHTML = '';
    shoppingList.forEach(item => {
        const listItem = document.createElement('li');
        listItem.innerHTML = `
        <span>${item.name}</span>
        <input type="number" value="${item.quantity}" min="1">
        <button class="remove-item">Remove</button>
        `;
        shoppingListItems.appendChild(listItem);
    });
}

// Save shopping list to localStorage
function saveShoppingList() {
    const shoppingListItems = document.querySelectorAll('#shopping-list-items li');
    const shoppingList = [];
    shoppingListItems.forEach(item => {
        const name = item.querySelector('span').textContent;
        const quantity = item.querySelector('input').value;
        shoppingList.push({ name, quantity });
    });
    localStorage.setItem('shoppingList', JSON.stringify(shoppingList));
}

// Remove item from shopping list
document.addEventListener('click', event => {
    if (event.target.classList.contains('remove-item')) {
        event.target.closest('li').remove();
        saveShoppingList();
    }
});

// Load the shopping list when the page loads
window.addEventListener('load', loadShoppingList);

// Load products when page loads
window.addEventListener('load', loadProducts);