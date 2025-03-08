// Load products from API
async function loadProducts() {
    const urlParams = new URLSearchParams(window.location.search);
    const currentCategory = urlParams.get("category");
    
    try {
        const response = await fetch(`/api/products${currentCategory ? `?catid=${currentCategory}` : ''}`);
        const products = await response.json();
        
        const productList = document.querySelector(".product-list");
        productList.innerHTML = products.map(product => `
            <div class="product">
                <a href="product.html?id=${product.pid}">
                    <img src="/images/products/${product.image_thumbnail}" alt="${product.name}">
                    <h3>${product.name}</h3>
                </a>
                <p>$${product.price}</p>
                <button class="add-to-cart">Add to Cart</button>
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
        console.error(err);
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