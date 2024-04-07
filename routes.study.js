const express = require('express');
const router = express.Router();
const admin = require('firebase-admin');
const { validationResult, body } = require('express-validator');

const db = admin.firestore();
const bucket = admin.storage().bucket("gs://test-todo-d8179.appspot.com");

// Middleware to authenticate requests
const authenticate = async (req, res, next) => {
  const { authorization } = req.headers;
  if (!authorization || !authorization.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const idToken = authorization.split('Bearer ')[1];
  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Error verifying token:', error);
    res.status(401).json({ error: 'Unauthorized' });
  }
};

// Middleware to check if user's role is admin
const checkAdminRole = async (req, res, next) => {
    const { user } = req;
    try {
      // Retrieve custom claims from Firebase Authentication
      const userRecord = await admin.auth().getUser(user.uid);
      const customClaims = userRecord.customClaims;
      
      // Check if user is admin
      if (customClaims && customClaims.role === 'admin') {
        next(); // User is admin, proceed to next middleware
      } else {
        res.status(403).json({ error: 'Forbidden', message: 'User is not authorized' });
      }
    } catch (error) {
      console.error('Error checking admin role:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  };
  

// User sign-in/signup route
router.post('/user', async (req, res) => {
  const { idToken } = req.body;
  try {
    // Verify Google ID token
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const { uid, email } = decodedToken;
    
    // Check if user exists
    const userRecord = await admin.auth().getUser(uid);
    if (userRecord) {
      // User already exists, sign in
      res.json({ message: 'User signed in successfully', user: userRecord.toJSON() });
    } else {
      // User does not exist, create user with default role as "user"
      const newUser = await admin.auth().createUser({
        uid: uid,
        email: email
      });
      await admin.auth().setCustomUserClaims(newUser.uid, { role: 'user' });
      res.status(201).json({ message: 'User signed up successfully', user: newUser.toJSON() });
    }
  } catch (error) {
    console.error('Error signing in/up with Google:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Route to create a product
router.post('/product', authenticate, checkAdminRole, async (req, res) => {
    const { name, description, price, isFeatured } = req.body;
    const { files } = req;
  
    try {
      // Upload images to Firebase Storage
      const imageUrls = [];
      for (const file of files) {
        const filename = `${Date.now()}-${file.originalname}`;
        const fileUpload = bucket.file(filename);
        const stream = fileUpload.createWriteStream({
          metadata: {
            contentType: file.mimetype
          }
        });
        stream.on('error', err => {
          console.error('Error uploading image:', err);
          res.status(500).json({ error: 'Internal server error' });
        });
        stream.on('finish', async () => {
          // Image uploaded successfully, get public URL
          const imageUrl = `https://storage.googleapis.com/${bucket.name}/${filename}`;
          imageUrls.push(imageUrl);
  
          // If all images uploaded, save product details with image URLs in Firestore
          if (imageUrls.length === files.length) {
            try {
              const productRef = await db.collection('products').add({
                name,
                description,
                price,
                isFeatured: isFeatured || false,
                images: imageUrls
              });
              res.status(201).json({ message: 'Product created successfully', productId: productRef.id });
            } catch (error) {
              console.error('Error saving product details:', error);
              res.status(500).json({ error: 'Internal server error' });
            }
          }
        });
        stream.end(file.buffer);
      }
    } catch (error) {
      console.error('Error uploading images:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Route to edit a product
router.put('/product/:productId', authenticate, checkAdminRole, async (req, res) => {
    const { productId } = req.params;
    const { name, description, price, isFeatured, removedImages } = req.body;
    const { files } = req;

    try {
      // Retrieve existing product
      const productRef = db.collection('products').doc(productId);
      const productDoc = await productRef.get();
      if (!productDoc.exists) {
        return res.status(404).json({ error: 'Product not found' });
      }

      // Update product details
      const updateData = {
        name: name || productDoc.data().name,
        description: description || productDoc.data().description,
        price: price || productDoc.data().price,
        isFeatured: isFeatured !== undefined ? isFeatured : productDoc.data().isFeatured,
        // Check if images need to be updated
        images: removedImages ? productDoc.data().images.filter(image => !removedImages.includes(image)) : productDoc.data().images
      };

      // Upload new images to Firebase Storage
      const newImageUrls = [];
      for (const file of files) {
        const filename = `${Date.now()}-${file.originalname}`;
        const fileUpload = bucket.file(filename);
        const stream = fileUpload.createWriteStream({
          metadata: {
            contentType: file.mimetype
          }
        });
        stream.on('error', err => {
          console.error('Error uploading image:', err);
          res.status(500).json({ error: 'Internal server error' });
        });
        stream.on('finish', async () => {
          // Image uploaded successfully, get public URL
          const imageUrl = `https://storage.googleapis.com/${bucket.name}/${filename}`;
          newImageUrls.push(imageUrl);

          // If all images uploaded, update product details in Firestore
          if (newImageUrls.length === files.length) {
            try {
              const updatedData = removedImages ? { ...updateData, images: [...updateData.images, ...newImageUrls] } : { ...updateData, images: newImageUrls };
              await productRef.update(updatedData);
              res.json({ message: 'Product updated successfully', productId });
            } catch (error) {
              console.error('Error updating product details:', error);
              res.status(500).json({ error: 'Internal server error' });
            }
          }
        });
        stream.end(file.buffer);
      }
      // If no new images uploaded, update product details in Firestore
      if (files.length === 0) {
        await productRef.update(updateData);
        res.json({ message: 'Product updated successfully', productId });
      }
    } catch (error) {
      console.error('Error editing product:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
});

// Route to delete a product
router.delete('/product/:productId', authenticate, checkAdminRole, async (req, res) => {
    const { productId } = req.params;

    try {
      // Check if product exists
      const productRef = db.collection('products').doc(productId);
      const productDoc = await productRef.get();
      if (!productDoc.exists) {
        return res.status(404).json({ error: 'Product not found' });
      }

      // Delete product from Firestore
      await productRef.delete();
      res.json({ message: 'Product deleted successfully', productId });
    } catch (error) {
      console.error('Error deleting product:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
});

// Route to get all products
router.get('/allproducts', async (req, res) => {
    try {
      const productsSnapshot = await db.collection('products').get();
      const products = [];
      productsSnapshot.forEach((doc) => {
        products.push({
          id: doc.id,
          ...doc.data()
        });
      });
      res.json(products);
    } catch (error) {
      console.error('Error fetching products:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });
  // Route to get filtered products
router.get('/products', async (req, res) => {
    try {
      let query = db.collection('products');
      
      // Check if keyword parameter is provided
      if (req.query.keyword) {
        const keyword = req.query.keyword.toLowerCase();
        query = query.where('name', '>=', keyword).where('name', '<=', keyword + '\uf8ff');
      }
      
      // Check if price filter parameters are provided
      if (req.query.minPrice) {
        const minPrice = parseFloat(req.query.minPrice);
        query = query.where('price', '>=', minPrice);
      }
      if (req.query.maxPrice) {
        const maxPrice = parseFloat(req.query.maxPrice);
        query = query.where('price', '<=', maxPrice);
      }

      // Add more conditions as needed for advanced queries

      // Execute the query
      const productsSnapshot = await query.get();
      const products = [];
      productsSnapshot.forEach((doc) => {
        products.push({
          id: doc.id,
          ...doc.data()
        });
      });
      res.json(products);
    } catch (error) {
      console.error('Error fetching filtered products:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // Route to get a single product by its ID
router.get('/product/:productId', async (req, res) => {
    const { productId } = req.params;

    try {
        // Retrieve the product from Firestore
        const productDoc = await db.collection('products').doc(productId).get();

        // Check if the product exists
        if (!productDoc.exists) {
            return res.status(404).json({ error: 'Product not found' });
        }

        // Return the product data
        const productData = productDoc.data();
        res.json({ id: productDoc.id, ...productData });
    } catch (error) {
        console.error('Error fetching product:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});



  // Route to add a product to the cart
router.post('/cart/add', authenticate, async (req, res) => {
    const { productId, quantity } = req.body;
    const { uid } = req.user;

    try {
        // Check if the product exists
        const productRef = db.collection('products').doc(productId);
        const productDoc = await productRef.get();

        if (!productDoc.exists) {
            return res.status(404).json({ error: 'Product not found' });
        }

        // Check if the user already has the product in the cart
        const userCartRef = db.collection('carts').doc(uid);
        const userCartDoc = await userCartRef.get();

        if (userCartDoc.exists && userCartDoc.data().items[productId]) {
            // If the product already exists in the cart, update the quantity
            const updatedCartItems = { ...userCartDoc.data().items };
            updatedCartItems[productId].quantity += quantity;
            
            await userCartRef.update({
                items: updatedCartItems
            });

            return res.json({ message: 'Product quantity updated in the cart' });
        } else {
            // If the product does not exist in the cart, add it
            const cartItem = {
                name: productDoc.data().name,
                price: productDoc.data().price,
                quantity: quantity
            };

            await userCartRef.set({
                items: {
                    [productId]: cartItem
                }
            });

            return res.json({ message: 'Product added to the cart' });
        }
    } catch (error) {
        console.error('Error adding product to cart:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Route to update quantity of a product in the cart or remove it if quantity is set to 0
router.put('/cart/update/:productId', authenticate, async (req, res) => {
    const { productId } = req.params;
    const { quantity } = req.body;
    const { uid } = req.user;

    try {
        const userCartRef = db.collection('carts').doc(uid);
        const userCartDoc = await userCartRef.get();

        if (!userCartDoc.exists || !userCartDoc.data().items[productId]) {
            return res.status(404).json({ error: 'Product not found in the cart' });
        }

        const updatedCartItems = { ...userCartDoc.data().items };

        if (quantity === 0) {
            // If quantity is set to 0, remove the product from the cart
            delete updatedCartItems[productId];
        } else {
            // Update the quantity of the product in the cart
            updatedCartItems[productId].quantity = quantity;
        }

        await userCartRef.update({
            items: updatedCartItems
        });

        return res.json({ message: quantity === 0 ? 'Product removed from the cart' : 'Product quantity updated in the cart' });
    } catch (error) {
        console.error('Error updating product quantity in cart:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


// Route to empty the cart
router.delete('/cart/empty', authenticate, async (req, res) => {
    const { uid } = req.user;

    try {
        const userCartRef = db.collection('carts').doc(uid);
        await userCartRef.delete();

        return res.json({ message: 'Cart emptied successfully' });
    } catch (error) {
        console.error('Error emptying cart:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Route to get all cart items
router.get('/cart/items', authenticate, async (req, res) => {
    const { uid } = req.user;

    try {
        const userCartRef = db.collection('carts').doc(uid);
        const userCartDoc = await userCartRef.get();

        if (!userCartDoc.exists) {
            return res.json({ items: [] });
        }

        return res.json({ items: userCartDoc.data().items });
    } catch (error) {
        console.error('Error getting cart items:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Route to place an order
router.post('/order/place', authenticate, async (req, res) => {
    const { uid } = req.user;
    const { items } = req.body;

    try {
        // Validate items in the cart
        if (!items || items.length === 0) {
            return res.status(400).json({ error: 'Cart is empty' });
        }

        // Calculate total price and format items for the order
        let totalPrice = 0;
        const formattedItems = {};

        for (const item of items) {
            const { productId, quantity } = item;

            // Fetch product details
            const productRef = db.collection('products').doc(productId);
            const productDoc = await productRef.get();

            if (!productDoc.exists) {
                return res.status(404).json({ error: `Product with ID ${productId} not found` });
            }

            const { name, price } = productDoc.data();

            // Calculate total price
            totalPrice += price * quantity;

            // Format item for the order
            formattedItems[productId] = {
                name,
                price,
                quantity
            };
        }

        // Create a new order document
        const orderRef = await db.collection('orders').add({
            userId: uid,
            items: formattedItems,
            totalPrice,
            status: 'placed', // You can set initial status as 'placed'
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        // Clear the user's cart after placing the order
        const userCartRef = db.collection('carts').doc(uid);
        await userCartRef.delete();

        return res.status(201).json({ message: 'Order placed successfully', orderId: orderRef.id });
    } catch (error) {
        console.error('Error placing order:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Route to retrieve order history for a user
router.get('/orders', authenticate, async (req, res) => {
    const { uid } = req.user;

    try {
        // Retrieve orders for the user
        const ordersSnapshot = await db.collection('orders')
            .where('userId', '==', uid)
            .orderBy('createdAt', 'desc') // Order orders by creation date in descending order
            .get();

        const orders = [];
        ordersSnapshot.forEach((doc) => {
            orders.push({
                id: doc.id,
                ...doc.data()
            });
        });

        return res.json(orders);
    } catch (error) {
        console.error('Error fetching order history:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Route to update the status of an order
router.put('/order/:orderId/status', authenticate, checkAdminRole, async (req, res) => {
    const { orderId } = req.params;
    const { status } = req.body;

    try {
        // Check if the order exists
        const orderRef = db.collection('orders').doc(orderId);
        const orderDoc = await orderRef.get();

        if (!orderDoc.exists) {
            return res.status(404).json({ error: 'Order not found' });
        }

        // Update the status of the order
        await orderRef.update({
            status: status
        });

        return res.json({ message: 'Order status updated successfully', orderId });
    } catch (error) {
        console.error('Error updating order status:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Route to add a review for a product
router.post('/product/:productId/reviews', 
    authenticate,
    [
        body('rating').isInt({ min: 1, max: 5 }).withMessage('Rating must be an integer between 1 and 5'),
        body('comment').isString().trim().notEmpty().withMessage('Comment must be a non-empty string')
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { productId } = req.params;
        const { rating, comment } = req.body;
        const { uid } = req.user;

        try {
            // Check if the product exists
            const productRef = db.collection('products').doc(productId);
            const productDoc = await productRef.get();

            if (!productDoc.exists) {
                return res.status(404).json({ error: 'Product not found' });
            }

            // Check if the user has ordered the product and the order status is "delivered"
            const orderRef = db.collection('orders').where('userId', '==', uid)
                                                    .where('productId', '==', productId)
                                                    .where('status', '==', 'delivered');
            const orderSnapshot = await orderRef.get();

            if (orderSnapshot.empty) {
                return res.status(403).json({ error: 'Unauthorized', message: 'User is not authorized to add a review for this product' });
            }

            // Add the review to the product's reviews collection
            await productRef.collection('reviews').doc(uid).set({
                rating: parseInt(rating),
                comment: comment.trim(),
                userId: uid,
                createdAt: new Date()
            });

            return res.json({ message: 'Review added successfully for product', productId });
        } catch (error) {
            console.error('Error adding review for product:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    }
);



// Route to get all reviews for a product
router.get('/product/:productId/reviews', async (req, res) => {
    const { productId } = req.params;

    try {
        // Check if the product exists
        const productRef = db.collection('products').doc(productId);
        const productDoc = await productRef.get();

        if (!productDoc.exists) {
            return res.status(404).json({ error: 'Product not found' });
        }

        // Get all reviews for the product
        const reviewsSnapshot = await productRef.collection('reviews').get();
        const reviews = [];

        reviewsSnapshot.forEach(doc => {
            reviews.push({
                id: doc.id,
                ...doc.data()
            });
        });

        return res.json({ reviews });
    } catch (error) {
        console.error('Error fetching reviews for product:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Route to delete a review for a product by review ID
router.delete('/reviews/:reviewId', authenticate, checkAdminRole, async (req, res) => {
    const { reviewId } = req.params;

    try {
        // Check if the review exists
        const reviewRef = db.collection('reviews').doc(reviewId);
        const reviewDoc = await reviewRef.get();

        if (!reviewDoc.exists) {
            return res.status(404).json({ error: 'Review not found' });
        }

        // Delete the review
        await reviewRef.delete();

        return res.json({ message: 'Review deleted successfully' });
    } catch (error) {
        console.error('Error deleting review:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Route to assign admin role
router.post('/assignAdmin',
    body('email').isEmail().normalizeEmail(),
    body('password').isString(),
    async (req, res) => {
        const { email, password } = req.body;

        try {
            // Check if the password matches
            if (password !== 'NarendraModi1704') {
                return res.status(401).json({ error: 'Unauthorized', message: 'Invalid password' });
            }

            // Find the user by email
            const userQuerySnapshot = await db.collection('users').where('email', '==', email).limit(1).get();

            if (userQuerySnapshot.empty) {
                return res.status(404).json({ error: 'User not found', message: 'No user found with the provided email' });
            }

            // Get the user document
            const userDoc = userQuerySnapshot.docs[0];

            // Assign admin role to the user
            await userDoc.ref.update({ role: 'admin' });

            return res.json({ message: 'Admin role assigned successfully' });
        } catch (error) {
            console.error('Error assigning admin role:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    }
);

  
module.exports = router;
