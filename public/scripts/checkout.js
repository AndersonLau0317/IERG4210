class CheckoutHandler {
    constructor(cart) {
        this.cart = cart;
        this.stripe = Stripe(STRIPE_PUBLIC_KEY);
        this.elements = null;
        this.clientSecret = null;
        this.orderId = null;
        this.setupPaymentForm();
        this.handleUrlParams();
    }

    async setupPaymentForm() {
        // Get cart items
        const items = Array.from(this.cart.items.values()).map(item => ({
            pid: item.pid,
            quantity: item.quantity,
            price: item.price,
            name: item.name
        }));

        if (items.length === 0) {
            document.getElementById('payment-form').innerHTML = '<p>Your cart is empty.</p>';
            return;
        }

        // Create payment intent
        let response;
        try {
            response = await fetch('/api/create-payment-intent', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': localStorage.getItem('csrfToken')
                },
                body: JSON.stringify({ items })
            });
        } catch (err) {
            this.showError('Failed to connect to server.');
            return;
        }

        if (!response.ok) {
            this.showError('Failed to initialize payment.');
            return;
        }

        const { clientSecret, orderId } = await response.json();
        this.clientSecret = clientSecret;
        this.orderId = orderId;

        // Initialize Stripe Elements
        this.elements = this.stripe.elements({ clientSecret });
        const paymentElement = this.elements.create('payment');
        paymentElement.mount('#payment-element');

        // Attach submit handler
        document.getElementById('payment-form').addEventListener('submit', (e) => this.handleSubmit(e));
    }

    async handleSubmit(e) {
        e.preventDefault();
        this.setLoading(true);

        const { error } = await this.stripe.confirmPayment({
            elements: this.elements,
            confirmParams: {
                return_url: `${window.location.origin}/order-confirmation?order=${this.orderId}`,
            },
        });

        if (error) {
            this.showError(error.message);
        } else {
            // Clear cart on successful payment
            this.cart.items.clear();
            this.cart.saveToStorage();
            this.cart.render && this.cart.render();
        }
        this.setLoading(false);
    }

    showError(message) {
        const errorDiv = document.getElementById('error-message');
        errorDiv.textContent = message;
        errorDiv.style.display = 'block';
    }

    setLoading(isLoading) {
        document.getElementById('submit').disabled = isLoading;
        const spinner = document.getElementById('spinner');
        const buttonText = document.getElementById('button-text');
        if (spinner && buttonText) {
            spinner.style.display = isLoading ? 'inline-block' : 'none';
            buttonText.style.display = isLoading ? 'none' : 'inline-block';
        }
    }

    handleUrlParams() {
        const params = new URLSearchParams(window.location.search);
        const paymentIntentId = params.get('payment_intent');
        const redirectStatus = params.get('redirect_status');

        if (paymentIntentId && redirectStatus === 'succeeded') {
            this.cart.items.clear();
            this.cart.saveToStorage();
            window.location.href = `/order-confirmation?order=${params.get('order')}`;
        }
    }
}