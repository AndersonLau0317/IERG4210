// Add to Cart functionality for product page
document.querySelector('.add-to-cart').addEventListener('click', () => {
    const productName = document.querySelector('.product-details h1').textContent;
    const productPrice = document.querySelector('.product-details p').textContent;
  
    const listItem = document.createElement('li');
    listItem.innerHTML = `
      <span>${productName}</span>
      <input type="number" value="1" min="1">
      <button class="remove-item">Remove</button>
    `;
    document.getElementById('shopping-list-items').appendChild(listItem);
  });
  
  // Remove item from shopping list
  document.addEventListener('click', event => {
    if (event.target.classList.contains('remove-item')) {
      event.target.closest('li').remove();
    }
  });