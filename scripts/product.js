// Sample product data
const products = [
    { id: 1, name: "Product 1", price: "$19.99", category: "category1", image: "images/product1-thumbnail.jpg" },
    { id: 2, name: "Product 2", price: "$29.99", category: "category2", image: "images/product2-thumbnail.jpg" },
];

// Get the current product ID from the URL
const urlParams = new URLSearchParams(window.location.search);
const productId = parseInt(urlParams.get("id"), 10);

// Find the product by ID
const product = products.find(p => p.id === productId);

// Display product details
const productDetails = document.querySelector(".product-details");
if (product) {
    productDetails.innerHTML = `
        <img src="${product.image}" alt="${product.name}">
        <h1>${product.name}</h1>
        <p>This is a detailed description of ${product.name}. It is a high-quality product with amazing features.</p>
        <p>${product.price}</p>
        <button class="add-to-cart">Add to Cart</button>
    `;
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

// Add to Cart functionality
document.querySelector('.add-to-cart').addEventListener('click', () => {
    const productName = product.name;
    const productPrice = product.price;

    const listItem = document.createElement('li');
    listItem.innerHTML = `
    <span>${productName}</span>
    <input type="number" value="1" min="1">
    <button class="remove-item">Remove</button>
    `;
    document.getElementById('shopping-list-items').appendChild(listItem);
    saveShoppingList();
});

// Remove item from shopping list
document.addEventListener('click', event => {
    if (event.target.classList.contains('remove-item')) {
        event.target.closest('li').remove();
        saveShoppingList();
    }
});

// Load the shopping list when the page loads
window.addEventListener('load', loadShoppingList);