// Sample product data
const products = [
    { id: 1, name: "Product 1", price: "$19.99", category: "category1", image: "images/product1-thumbnail.jpg" },
    { id: 2, name: "Product 2", price: "$29.99", category: "category2", image: "images/product2-thumbnail.jpg" },
];

// Get the current category from the URL
const urlParams = new URLSearchParams(window.location.search);
const currentCategory = urlParams.get("category");

// Filter products by category
const filteredProducts = currentCategory
    ? products.filter(product => product.category === currentCategory)
    : products;

// Display filtered products
const productList = document.querySelector(".product-list");
filteredProducts.forEach(product => {
    const productDiv = document.createElement("div");
    productDiv.classList.add("product");
    productDiv.innerHTML = `
      <a href="product.html?id=${product.id}">
        <img src="${product.image}" alt="${product.name}">
        <h3>${product.name}</h3>
      </a>
      <p>${product.price}</p>
      <button class="add-to-cart">Add to Cart</button>
    `;
    productList.appendChild(productDiv);
});

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
    });
});

// Remove item from shopping list
document.addEventListener('click', event => {
    if (event.target.classList.contains('remove-item')) {
        event.target.closest('li').remove();
    }
});