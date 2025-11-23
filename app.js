require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const { PrismaClient } = require("@prisma/client");
// In your backend - api/upload.js
const cloudinary = require("cloudinary").v2;
const multer = require("multer");

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.API_KEY,
  api_secret: process.env.API_SECRET,
});

const app = express();
const prisma = new PrismaClient();
// Configure multer for file upload
const upload = multer({ storage: multer.memoryStorage() });

app.use(cors());
app.use(express.json());

// Authentication routes
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password || !name) {
      return res.status(400).json({ error: "All fields are required" });
    }
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ error: "Email already registered" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { email, password: hashedPassword, name },
    });
    const { password: _, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const { password: _, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
// Delete account permanently
app.delete("/api/auth/account", async (req, res) => {
  try {
    const { userId, password } = req.body;

    if (!userId || !password) {
      return res.status(400).json({
        error: "User ID and password are required",
      });
    }

    // Find the user
    const user = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid password" });
    }

    // Start a transaction to delete all related data
    await prisma.$transaction(async (tx) => {
      // Delete user's related records first (adjust based on your schema)
      // Example: if you have related tables like posts, comments, etc.

      // Delete user's sessions/tokens if you have them
      await tx.session.deleteMany({
        where: { userId: userId },
      });

      // Delete user's other related data
      // Add more delete operations for your specific related tables

      // Finally delete the user
      await tx.user.delete({
        where: { id: userId },
      });
    });

    res.json({
      success: true,
      message: "Account deleted permanently",
    });
  } catch (error) {
    console.error("Error deleting account:", error);
    res.status(500).json({
      error: "Failed to delete account",
      details: error.message,
    });
  }
});

// Admin authentication route
app.post("/api/auth/admin-login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    if (user.role !== "ADMIN") {
      return res
        .status(403)
        .json({ error: "Access denied. Admin privileges required." });
    }
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const { password: _, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Business routes
const validateBusinessData = (data) => {
  const required = [
    "name",
    "description",
    "category",
    "phone",
    "email",
    "location",
    "businessType",
    "ownerId",
  ];
  for (const field of required) {
    if (!data[field]) return `${field} is required`;
  }
  return null;
};

// Business routes
const validatedPlanData = (data) => {
  const required = [
    "name",
    "description",
    "allowedBusinesses",
    "allowedProducts",
    "userId",
    "profile_status",
    "price",
  ];

  for (const field of required) {
    // Special handling for price since 0 is a valid value but falsy
    if (field === "price") {
      if (data[field] === undefined || data[field] === null) {
        return `${field} is required`;
      }
    }
    // For other fields, check if they exist and have truthy values
    else if (!data[field]) {
      return `${field} is required`;
    }
  }
  return null;
};

const isAdmin = async (userId) => {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { role: true },
  });
  return user?.role === "ADMIN";
};

app.post("/api/upload", upload.single("image"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No image file provided" });
    }

    // Convert buffer to base64
    const b64 = Buffer.from(req.file.buffer).toString("base64");
    const dataURI = "data:" + req.file.mimetype + ";base64," + b64;

    // Upload to Cloudinary
    const result = await cloudinary.uploader.upload(dataURI, {
      folder: "caafiCare",
      resource_type: "auto",
    });

    res.json({
      imageUrl: result.secure_url,
      publicId: result.public_id,
    });
  } catch (error) {
    console.error("Upload error:", error);
    res.status(500).json({ error: "Failed to upload image" });
  }
});

// CREATE plan
const validateUpdateUserData = (data) => {
  // Check if any field is provided
  if (Object.keys(data).length === 0) {
    return "No fields provided for update.";
  }

  // Basic validation for name
  if (
    data.name !== undefined && // Check only if field is present
    (typeof data.name !== "string" || data.name.trim().length < 2)
  ) {
    return "Name must be a valid string of at least 2 characters.";
  }

  // Basic validation for email format
  if (data.email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(data.email)) {
      return "Invalid email format.";
    }
  }

  // 🌟 NEW: Basic validation for password 🌟
  if (data.password !== undefined) {
    if (typeof data.password !== "string" || data.password.length < 8) {
      return "Password must be at least 8 characters long.";
    }
    // Optionally check for confirmation password if needed, but not required by this API signature
  }

  // Phone and Location can be optional and free-form strings
  if (data.phone !== undefined && typeof data.phone !== "string") {
    return "Phone must be a string.";
  }
  if (data.location !== undefined && typeof data.location !== "string") {
    return "Location must be a string.";
  }

  return null; // Validation passed
};

const isAuthenticated = (req, res, next) => {
  // SECURITY NOTE: This is a placeholder. In production, this should validate a JWT token.
  if (req.headers["x-user-id"]) {
    req.userId = req.headers["x-user-id"]; // Assuming the auth middleware attaches the user ID
    next();
  } else {
    res.status(401).json({
      error: "Authentication required. Please provide 'x-user-id' header.",
    });
  }
};

const validateUpdateData = (data) => {
  // In a real app, check field formats (e.g., price is numeric, email is valid)
  if (data.price && isNaN(parseFloat(data.price))) {
    return "Price must be a valid number.";
  }
  return null;
};

// --- 🌟 UPDATED UPDATE USER API ROUTE 🌟 ---
app.patch("/api/users/:id", async (req, res) => {
  const userIdToUpdate = parseInt(req.params.id, 10);
  const updateData = req.body;

  // 1. Basic Validation
  if (isNaN(userIdToUpdate)) {
    return res.status(400).json({ error: "Invalid User ID provided." });
  }

  const validationError = validateUpdateUserData(updateData);
  if (validationError) {
    return res.status(400).json({ error: validationError });
  }

  try {
    // 3. Prepare data for Prisma
    const dataToUpdate = {};

    // Copy simple fields if they exist
    if (updateData.name !== undefined) dataToUpdate.name = updateData.name;
    if (updateData.email !== undefined) dataToUpdate.email = updateData.email;
    if (updateData.phone !== undefined) dataToUpdate.phone = updateData.phone;
    if (updateData.location !== undefined)
      dataToUpdate.location = updateData.location;

    // 🌟 CHANGE: Handle Password Hashing 🌟
    if (updateData.password !== undefined) {
      const hashedPassword = await bcrypt.hash(updateData.password, 10);
      dataToUpdate.password = hashedPassword;
    }

    if (Object.keys(dataToUpdate).length === 0) {
      return res
        .status(400)
        .json({ error: "No valid fields provided for update." });
    }

    // 4. Update the user in the database
    const updatedUser = await prisma.user.update({
      where: { id: userIdToUpdate },
      data: dataToUpdate,
      // Select fields to return to the client (EXCLUDE PASSWORD)
      select: {
        id: true,
        email: true,
        name: true,
        phone: true,
        location: true,
        role: true,
        plan_id: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    // 5. Success Response
    res.json(updatedUser);
  } catch (error) {
    console.error("Error updating user profile:", error);

    // 6. Handle unique constraint error (e.g., email already exists)
    if (error.code === "P2002" && error.meta?.target?.includes("email")) {
      return res.status(409).json({
        error: "This email is already registered to another account.",
      });
    }

    res
      .status(500)
      .json({ error: "Failed to update profile due to a server error." });
  }
});

app.post("/api/plans", async (req, res) => {
  try {
    const validationError = validatedPlanData(req.body);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }
    const business = await prisma.plans.create({
      data: { ...req.body },
    });
    res.json(business);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// GET all plans
app.get("/api/plans", async (req, res) => {
  try {
    const plans = await prisma.plans.findMany({
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true,
          },
        },
      },
      orderBy: {
        price: "asc",
      },
    });
    res.json(plans);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// GET single plan
app.get("/api/plans/:id", async (req, res) => {
  try {
    const plan = await prisma.plans.findUnique({
      where: { id: parseInt(req.params.id) },
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true,
          },
        },
      },
    });

    if (!plan) {
      return res.status(404).json({ error: "Plan not found" });
    }

    res.json(plan);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// UPDATE plan
app.put("/api/plans/:id", async (req, res) => {
  try {
    const validationError = validatedPlanData(req.body);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    const plan = await prisma.plans.update({
      where: { id: parseInt(req.params.id) },
      data: { ...req.body },
    });

    res.json(plan);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// DELETE plan
app.delete("/api/plans/:id", async (req, res) => {
  try {
    await prisma.plans.delete({
      where: { id: parseInt(req.params.id) },
    });

    res.json({ message: "Plan deleted successfully" });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// GET user's current usage - FIXED with enum values
app.get("/api/users/:userId/usage", async (req, res) => {
  try {
    const userId = parseInt(req.params.userId);

    // Get user with businesses and products - REMOVE the status filter for now
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        businesses: true, // Remove where clause for now
        products: true, // Remove where clause for now
      },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Get the active plan using the user's plan_id
    let activePlan = null;
    if (user.plan_id) {
      activePlan = await prisma.plans.findUnique({
        where: { id: user.plan_id },
      });
    }

    // If no plan_id set, get the first plan associated with the user
    if (!activePlan) {
      const userPlans = await prisma.plans.findMany({
        where: { userId: user.id },
        take: 1,
        orderBy: { createdAt: "desc" },
      });
      activePlan = userPlans.length > 0 ? userPlans[0] : null;
    }

    // Fallback to default plan if no plan found
    if (!activePlan) {
      activePlan = await prisma.plans.findUnique({
        where: { id: 1 }, // Default plan ID
      });
    }

    if (!activePlan) {
      return res.status(400).json({ error: "No plan configuration found" });
    }

    // Count only ACTIVE or APPROVED businesses/products (adjust based on your enum)
    const activeBusinesses = user.businesses.filter(
      (business) =>
        business.status === "ACTIVE" || business.status === "APPROVED"
    );

    const activeProducts = user.products.filter(
      (product) => product.status === "ACTIVE" || product.status === "APPROVED"
    );

    const usage = {
      plan: activePlan,
      businesses: {
        count: activeBusinesses.length,
        limit: activePlan.allowedBusinesses,
        remaining: Math.max(
          0,
          activePlan.allowedBusinesses - activeBusinesses.length
        ),
      },
      products: {
        count: activeProducts.length,
        limit: activePlan.allowedProducts,
        remaining: Math.max(
          0,
          activePlan.allowedProducts - activeProducts.length
        ),
      },
    };

    res.json(usage);
  } catch (error) {
    console.error("Error fetching user usage:", error);
    res.status(500).json({ error: error.message });
  }
});

// 🌟 UPDATED: app.post("/api/businesses") 🌟
app.post("/api/businesses", async (req, res) => {
  try {
    // 1. Run the updated server-side validation
    // This validation must now check for 3 images and exclude businessType validation.
    const validationError = validateBusinessData(req.body);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    const { ownerId } = req.body;

    // 2. Limit Check Logic (remains the same)
    const user = await prisma.user.findUnique({
      where: { id: ownerId },
      include: {
        businesses: {
          where: {
            status: "ACTIVE",
          },
        },
      },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    let activePlan = null;
    if (user.plan_id) {
      activePlan = await prisma.plans.findUnique({
        where: { id: user.plan_id },
      });
    }

    if (!activePlan) {
      activePlan = await prisma.plans.findUnique({
        where: { id: 1 }, // Default plan ID
      });
    }

    if (!activePlan) {
      return res.status(400).json({ error: "No active plan found" });
    }

    const businessLimit = activePlan.allowedBusinesses;
    const currentBusinessCount = user.businesses.length;

    if (currentBusinessCount >= businessLimit) {
      return res.status(403).json({
        error: `Business limit reached. You can only create ${businessLimit} business(es) with your ${activePlan.name}.`,
        code: "BUSINESS_LIMIT_REACHED",
        currentCount: currentBusinessCount,
        limit: businessLimit,
      });
    }

    // 3. Create Business (uses req.body, which now contains the image string and hardcoded businessType)
    const business = await prisma.business.create({
      data: { ...req.body },
    });

    res.json(business);
  } catch (error) {
    console.error("Error creating business:", error);
    res.status(400).json({ error: error.message });
  }
});

// Enhanced product creation with plan validation
// NOTE: This server-side validator is now integrated based on your request.
const validateProductData = (data) => {
  // 🌟 MODIFIED REQUIRED FIELDS: Added 'image' (for the URL string) 🌟
  const required = [
    "name",
    "description",
    "price",
    "category",
    "userId",
    "location",
    "image", // Ensure the comma-separated URL string is present
  ];
  for (const field of required) {
    if (!data[field]) return `${field} is required`;
  }
  if (isNaN(parseFloat(data.price)) || parseFloat(data.price) <= 0) {
    return "Price must be a positive number";
  }
  return null;
};

app.post("/api/products", async (req, res) => {
  try {
    // 🌟 Using the provided server-side validation 🌟
    const validationError = validateProductData(req.body);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    // Deconstruct fields, ensuring we parse the price if needed
    const { userId, price, ...otherData } = req.body;

    // Check user's product limit
    const userUsage = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        plan: true,
        products: {
          where: {
            status: "ACTIVE", // Only count active products
          },
        },
      },
    });

    if (!userUsage) {
      return res.status(404).json({ error: "User not found" });
    }

    const activePlan = userUsage.plan;
    if (!activePlan) {
      return res.status(400).json({ error: "No active plan found" });
    }

    const productLimit = activePlan.allowedProducts;
    const currentProductCount = userUsage.products.length;

    if (currentProductCount >= productLimit) {
      return res.status(403).json({
        error: `Product limit reached. You can only create ${productLimit} product(s) with your ${activePlan.name}.`,
        code: "PRODUCT_LIMIT_REACHED",
        currentCount: currentProductCount,
        limit: productLimit,
      });
    }

    // Prepare data for Prisma
    const product = await prisma.product.create({
      data: {
        ...otherData,
        userId: userId, // Ensure userId is included
        price: parseFloat(price), // Explicitly convert price to a number
        status: otherData.status || "PENDING", // Use status from body or default to PENDING
      },
    });

    res.json(product);
  } catch (error) {
    console.error("Error creating product:", error);
    res.status(400).json({
      error:
        error.message || "An unknown error occurred during product creation.",
    });
  }
});

app.get("/api/businesses", async (req, res) => {
  try {
    const businesses = await prisma.business.findMany({
      where: { status: "APPROVED" },
    });
    res.json(businesses);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.patch("/api/businesses/:id", isAuthenticated, async (req, res) => {
  const currentUserId = req.userId; // Logged-in user's ID
  const businessId = req.params.id; // Business ID from URL parameter

  // Destructure all editable fields from the request body, including 'location'
  const {
    name,
    description,
    category,
    phone,
    email,
    images,
    location,
    ...updateData
  } = req.body;

  if (!businessId) {
    return res.status(400).json({ error: "Business ID is required." });
  }

  // Check if at least one field is provided for update
  const providedFields = {
    name,
    description,
    category,
    phone,
    email,
    images,
    location,
  };
  if (Object.values(providedFields).every((val) => val === undefined)) {
    return res.status(400).json({ error: "No fields provided for update." });
  }

  try {
    // 1. Verify ownership (Find the business and check its ownerId)
    const existingBusiness = await prisma.business.findUnique({
      where: { id: businessId },
      select: { ownerId: true },
    });

    if (!existingBusiness) {
      return res.status(404).json({ error: "Business listing not found." });
    }

    // Security check: only the owner can update the business
    if (existingBusiness.ownerId !== currentUserId) {
      return res
        .status(403)
        .json({ error: "Forbidden: You do not own this business listing." });
    }

    // Prepare update data dynamically
    const dataToUpdate = {
      ...(name && { name }),
      ...(description && { description }),
      ...(category && { category }),
      ...(phone && { phone }),
      ...(email && { email }),
      ...(images && { images }),
      ...(location && { location }), // Include location
      // Mandatory for any update: reset status and update timestamp
      status: "PENDING",
      updatedAt: new Date(),
    };

    // 2. Perform the update
    const updatedBusiness = await prisma.business.update({
      where: { id: businessId },
      data: dataToUpdate,
    });

    res.status(200).json({
      message: "Business updated successfully and reset to PENDING review.",
      business: updatedBusiness,
    });
  } catch (error) {
    console.error("Error updating business:", error);
    res.status(500).json({ error: "Failed to update business listing." });
  }
});

app.patch("/api/products/:id", isAuthenticated, async (req, res) => {
  const currentUserId = req.userId; // Logged-in user's ID
  const productId = req.params.id; // Product ID from URL parameter

  // Destructure editable fields (removed 'inStock', added 'category' and 'location')
  const { name, description, price, category, location, ...updateData } =
    req.body;

  if (!productId) {
    return res.status(400).json({ error: "Product ID is required." });
  }
  console.log(req.body);
  // Check if at least one field is provided for update
  if (!name && !description && !price && !category && !location) {
    return res.status(400).json({ error: "No fields provided for update." });
  }

  // Validate data using the mock function
  const validationError = validateUpdateData(req.body);
  if (validationError) {
    return res.status(400).json({ error: validationError });
  }

  // Prepare price for update if present
  let parsedPrice;
  if (price !== undefined) {
    // Explicitly parse price to float, consistent with your POST endpoint
    parsedPrice = parseFloat(price);
  }

  try {
    // 1. Verify ownership (Find the product and check its owner's ID)
    const existingProduct = await prisma.product.findUnique({
      where: { id: productId },
      select: { userId: true }, // Assuming the owner field is named 'userId'
    });

    if (!existingProduct) {
      return res.status(404).json({ error: "Product listing not found." });
    }

    // Security check: only the owner can update the product
    if (existingProduct.userId !== currentUserId) {
      return res
        .status(403)
        .json({ error: "Forbidden: You do not own this product listing." });
    }

    // Prepare update data dynamically
    const dataToUpdate = {
      ...(name && { name }),
      ...(description && { description }),
      ...(price !== undefined && { price: parsedPrice }),
      ...(category && { category }), // Include category
      ...(location && { location }), // Include location
      // Mandatory for any update: reset status and update timestamp
      status: "PENDING",
      updatedAt: new Date(),
    };

    // 2. Perform the update
    const updatedProduct = await prisma.product.update({
      where: { id: productId },
      data: dataToUpdate,
    });

    res.status(200).json({
      message: "Product updated successfully and reset to PENDING review.",
      product: updatedProduct,
    });
  } catch (error) {
    console.error("Error updating product:", error);
    res.status(500).json({ error: "Failed to update product listing." });
  }
});

// Get all businesses (for admin)
app.get("/api/admin/businesses", async (req, res) => {
  try {
    const businesses = await prisma.business.findMany({
      include: { owner: { select: { name: true, email: true } } },
    });
    res.json(businesses);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.patch("/api/businesses/:id/status", async (req, res) => {
  try {
    const { id } = req.params;
    const { status, userId } = req.body;

    if (!userId) {
      return res.status(401).json({ error: "User ID is required" });
    }

    const isUserAdmin = await isAdmin(userId);
    if (!isUserAdmin) {
      return res
        .status(403)
        .json({ error: "Only admins can update business status" });
    }

    if (!["PENDING", "APPROVED", "REJECTED"].includes(status)) {
      return res.status(400).json({ error: "Invalid status value" });
    }

    const business = await prisma.business.update({
      where: { id },
      data: { status },
    });
    res.json(business);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

const processProductData = (product) => {
  if (product.image && typeof product.image === "string") {
    // Split the comma-separated string into an array of URLs, trimming whitespace
    const imagesArray = product.image
      .split(",")
      .map((url) => url.trim())
      .filter((url) => url.length > 0);
    return {
      ...product,
      images: imagesArray, // New field with array of URLs
      primaryImage: imagesArray[0] || null, // Optional: for quick access to the main image
      // We keep the original 'image' field for compatibility, but the client should use 'images' or 'primaryImage'
    };
  }
  return {
    ...product,
    images: [],
    primaryImage: null,
  };
};

// --- Product Listing API ---
app.get("/api/products", async (req, res) => {
  try {
    const products = await prisma.product.findMany({
      where: { status: "APPROVED" },
    });

    // 🌟 CHANGE: Process the image field for the client 🌟
    const processedProducts = products.map(processProductData);

    res.json(processedProducts);
  } catch (error) {
    console.error("Error fetching products:", error);
    res.status(400).json({ error: error.message });
  }
});

// Get all products (for admin)
app.get("/api/admin/products", async (req, res) => {
  try {
    const products = await prisma.product.findMany({
      include: { user: { select: { name: true, email: true } } },
    });
    res.json(products);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.patch("/api/products/:id/status", async (req, res) => {
  try {
    const { id } = req.params;
    const { status, userId } = req.body;

    if (!userId) {
      return res.status(401).json({ error: "User ID is required" });
    }

    const isUserAdmin = await isAdmin(userId);
    if (!isUserAdmin) {
      return res
        .status(403)
        .json({ error: "Only admins can update product status" });
    }

    if (!["PENDING", "APPROVED", "REJECTED"].includes(status)) {
      return res.status(400).json({ error: "Invalid status value" });
    }

    const product = await prisma.product.update({
      where: { id },
      data: { status },
    });
    res.json(product);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Professional routes
const validateProfessionalData = (data) => {
  const required = [
    "userId",
    "profession",
    "specialty",
    "experience",
    "location",
    "phone",
    "email",
  ];
  for (const field of required) {
    if (!data[field]) return `${field} is required`;
  }
  return null;
};

app.post("/api/professionals", async (req, res) => {
  try {
    const validationError = validateProfessionalData(req.body);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }
    const professional = await prisma.professional.create({
      data: { ...req.body },
    });
    res.json(professional);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get("/api/professionals", async (req, res) => {
  try {
    const professionals = await prisma.professional.findMany({
      where: { status: "APPROVED" },
    });
    res.json(professionals);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Backend APIs for approval system

// Get pending businesses
app.get("/api/businesses/pending", async (req, res) => {
  try {
    const pendingBusinesses = await prisma.business.findMany({
      where: { status: "PENDING" },
      include: {
        owner: {
          select: {
            name: true,
            email: true,
          },
        },
      },
      orderBy: {
        submittedDate: "asc",
      },
    });
    res.json(pendingBusinesses);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Approve business
app.put("/api/businesses/:id/approve", async (req, res) => {
  try {
    const { id } = req.params;

    const business = await prisma.business.update({
      where: { id: parseInt(id) },
      data: { status: "APPROVED" },
    });

    res.json(business);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Reject business
app.put("/api/businesses/:id/reject", async (req, res) => {
  try {
    const { id } = req.params;

    const business = await prisma.business.update({
      where: { id: parseInt(id) },
      data: { status: "REJECTED" },
    });

    res.json(business);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Get pending professionals
app.get("/api/professionals/pending", async (req, res) => {
  try {
    const pendingProfessionals = await prisma.professional.findMany({
      where: { status: "PENDING" },
      include: {
        user: {
          select: {
            name: true,
            email: true,
          },
        },
      },
      orderBy: {
        submittedDate: "asc",
      },
    });
    res.json(pendingProfessionals);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get professional's products
app.get("/api/professionals/:id/products", async (req, res) => {
  try {
    const { id } = req.params;

    const products = await prisma.product.findMany({
      where: {
        userId: parseInt(id),
        status: "APPROVED", // Only show approved products
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    const formattedProducts = products.map((product) => ({
      id: product.id,
      name: product.name,
      description: product.description,
      price: product.price,
      category: product.category,
      image: product.image,
      status: product.status,
      stockQuantity: product.stockQuantity || 0,
      location: product.location,
      specifications: product.specifications
        ? JSON.parse(product.specifications)
        : [],
      materials: product.materials ? JSON.parse(product.materials) : [],
      dimensions: product.dimensions,
      weight: product.weight,
      madeToOrder: product.madeToOrder || false,
      productionTime: product.productionTime,
      createdAt: product.createdAt,
      updatedAt: product.updatedAt,
    }));

    res.json(formattedProducts);
  } catch (error) {
    console.error("Error fetching professional products:", error);
    res.status(500).json({ error: "Failed to fetch products" });
  }
});

// Get approved businesses
app.get("/api/businesses/approved", async (req, res) => {
  try {
    const approvedBusinesses = await prisma.business.findMany({
      where: {
        status: "APPROVED",
      },
      include: {
        owner: {
          select: {
            name: true,
            email: true,
          },
        },
      },
      orderBy: {
        submittedDate: "desc",
      },
    });

    res.json(approvedBusinesses);
  } catch (error) {
    console.error("Error fetching approved businesses:", error);
    res.status(500).json({ error: "Failed to fetch approved businesses" });
  }
});

// Get business by ID
app.get("/api/businesses/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const business = await prisma.business.findUnique({
      where: { id: parseInt(id) },
      include: {
        owner: {
          select: {
            name: true,
            email: true,
          },
        },
      },
    });

    if (!business) {
      return res.status(404).json({ error: "Business not found" });
    }

    res.json(business);
  } catch (error) {
    console.error("Error fetching business:", error);
    res.status(500).json({ error: "Failed to fetch business" });
  }
});

// Get business products
app.get("/api/businesses/:id/products", async (req, res) => {
  try {
    const { id } = req.params;

    // First get the business to find the owner
    const business = await prisma.business.findUnique({
      where: { id: parseInt(id) },
    });

    if (!business) {
      return res.status(404).json({ error: "Business not found" });
    }

    // Get products by the business owner
    const products = await prisma.product.findMany({
      where: {
        userId: business.ownerId,
        status: "APPROVED", // Only show approved products
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    res.json(products);
  } catch (error) {
    console.error("Error fetching business products:", error);
    res.status(500).json({ error: "Failed to fetch business products" });
  }
});

// Reject professional
app.put("/api/professionals/:id/reject", async (req, res) => {
  try {
    const { id } = req.params;

    const professional = await prisma.professional.update({
      where: { id: parseInt(id) },
      data: { status: "REJECTED" },
    });

    res.json(professional);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Get pending products
app.get("/api/products/pending", async (req, res) => {
  try {
    const pendingProducts = await prisma.product.findMany({
      where: { status: "PENDING" },
      include: {
        user: {
          select: {
            name: true,
            email: true,
          },
        },
      },
      orderBy: {
        submittedDate: "asc",
      },
    });
    res.json(pendingProducts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/products/:id", async (req, res) => {
  try {
    const productId = parseInt(req.params.id);

    // Validate that the ID is a valid number
    if (isNaN(productId)) {
      return res.status(400).json({ error: "Invalid product ID" });
    }

    const product = await prisma.product.findUnique({
      where: {
        id: productId,
      },
    });

    if (!product) {
      return res.status(404).json({ error: "Product not found" });
    }

    res.json(product);
  } catch (error) {
    console.error("Error fetching product:", error);
    res.status(500).json({ error: error.message });
  }
});
// Approve product
app.put("/api/products/:id/approve", async (req, res) => {
  try {
    const { id } = req.params;

    const product = await prisma.product.update({
      where: { id: parseInt(id) },
      data: { status: "APPROVED" },
    });

    res.json(product);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Approve professional
app.put("/api/professionals/:id/approve", async (req, res) => {
  try {
    const { id } = req.params;

    const professional = await prisma.professional.update({
      where: { id: parseInt(id) },
      data: { status: "APPROVED" },
    });

    res.json(professional);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Reject product
app.put("/api/products/:id/reject", async (req, res) => {
  try {
    const { id } = req.params;

    const product = await prisma.product.update({
      where: { id: parseInt(id) },
      data: { status: "REJECTED" },
    });

    res.json(product);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// ✅ Place this ABOVE "/api/professionals/:id"
app.get("/api/professionals/approved", async (req, res) => {
  try {
    const approvedProfessionals = await prisma.professional.findMany({
      where: { status: "APPROVED" },
      include: {
        user: { select: { id: true, name: true, email: true } },
      },
      orderBy: { submittedDate: "desc" },
    });

    const formattedProfessionals = approvedProfessionals.map(
      (professional) => ({
        id: professional.id,
        userId: professional.userId,
        userName: professional.user.name,
        userEmail: professional.user.email,
        profession: professional.profession,
        specialty: professional.specialty,
        experience: professional.experience,
        location: professional.location,
        phone: professional.phone,
        email: professional.email,
        image: professional.image,
        status: professional.status,
        submittedDate: professional.submittedDate,
        createdAt: professional.createdAt,
        updatedAt: professional.updatedAt,
      })
    );

    res.status(200).json(formattedProfessionals);
  } catch (error) {
    console.error("❌ Error fetching approved professionals:", error);
    res.status(500).json({ error: "Failed to fetch approved professionals" });
  }
});

// ✅ Then this goes AFTER
app.get("/api/professionals/:id", async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "Invalid ID" });

    const professional = await prisma.professional.findUnique({
      where: { id },
      include: {
        user: { select: { id: true, name: true, email: true } },
      },
    });

    if (!professional)
      return res.status(404).json({ error: "Professional not found" });

    res.json(professional);
  } catch (error) {
    console.error("Error in professional API:", error);
    res.status(500).json({ error: "Failed to fetch professional" });
  }
});

// Get all professionals (for admin)
app.get("/api/admin/professionals", async (req, res) => {
  try {
    const professionals = await prisma.professional.findMany({
      include: { user: { select: { name: true, email: true } } },
    });
    res.json(professionals);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.patch("/api/professionals/:id/status", async (req, res) => {
  try {
    const { id } = req.params;
    const { status, userId } = req.body;

    if (!userId) {
      return res.status(401).json({ error: "User ID is required" });
    }

    const isUserAdmin = await isAdmin(userId);
    if (!isUserAdmin) {
      return res
        .status(403)
        .json({ error: "Only admins can update professional status" });
    }

    if (!["PENDING", "APPROVED", "REJECTED"].includes(status)) {
      return res.status(400).json({ error: "Invalid status value" });
    }

    const professional = await prisma.professional.update({
      where: { id },
      data: { status },
    });
    res.json(professional);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Plan Upgrade Request APIs

// POST - Create upgrade request
app.post("/api/upgrade-requests", async (req, res) => {
  try {
    const {
      userId,
      currentPlanId,
      requestedPlanId,
      amount,
      paymentMethod,
      phoneNumber,
      screenshot,
    } = req.body;

    // Validate required fields
    if (
      !userId ||
      !currentPlanId ||
      !requestedPlanId ||
      !amount ||
      !paymentMethod ||
      !phoneNumber
    ) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const upgradeRequest = await prisma.planUpgradeRequest.create({
      data: {
        userId: parseInt(userId),
        currentPlanId: parseInt(currentPlanId),
        requestedPlanId: parseInt(requestedPlanId),
        amount: parseFloat(amount),
        paymentMethod,
        phoneNumber,
        screenshot,
        status: "PENDING",
      },
      include: {
        user: {
          select: { id: true, name: true, email: true },
        },
        currentPlan: true,
        requestedPlan: true,
      },
    });

    res.json(upgradeRequest);
  } catch (error) {
    console.error("Error creating upgrade request:", error);
    res.status(400).json({ error: error.message });
  }
});

// GET - All upgrade requests (for admin)
app.get("/api/upgrade-requests", async (req, res) => {
  try {
    const { status } = req.query;

    const where = {};
    if (status) {
      where.status = status;
    }

    const requests = await prisma.planUpgradeRequest.findMany({
      where,
      include: {
        user: {
          select: { id: true, name: true, email: true, phone: true },
        },
        currentPlan: true,
        requestedPlan: true,
      },
      orderBy: { createdAt: "desc" },
    });

    res.json(requests);
  } catch (error) {
    console.error("Error fetching upgrade requests:", error);
    res.status(500).json({ error: error.message });
  }
});

// PUT - Update upgrade request status (admin only)
app.put("/api/upgrade-requests/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { status, adminNotes } = req.body;

    if (!status) {
      return res.status(400).json({ error: "Status is required" });
    }

    const request = await prisma.planUpgradeRequest.update({
      where: { id: parseInt(id) },
      data: { status, adminNotes },
      include: {
        user: true,
        currentPlan: true,
        requestedPlan: true,
      },
    });

    // If approved, update user's plan
    if (status === "APPROVED") {
      await prisma.user.update({
        where: { id: request.userId },
        data: { plan_id: request.requestedPlanId },
      });

      // Here you can send notification to user about approval
      console.log(
        `User ${request.userId} plan upgraded to ${request.requestedPlanId}`
      );
    }

    res.json(request);
  } catch (error) {
    console.error("Error updating upgrade request:", error);
    res.status(400).json({ error: error.message });
  }
});

// GET - User's upgrade requests
app.get("/api/users/:userId/upgrade-requests", async (req, res) => {
  try {
    const { userId } = req.params;

    const requests = await prisma.planUpgradeRequest.findMany({
      where: { userId: parseInt(userId) },
      include: {
        currentPlan: true,
        requestedPlan: true,
      },
      orderBy: { createdAt: "desc" },
    });

    res.json(requests);
  } catch (error) {
    console.error("Error fetching user upgrade requests:", error);
    res.status(500).json({ error: error.message });
  }
});

// GET - All upgrade requests with filtering (FIXED)
app.get("/api/admin/upgrade-requests", async (req, res) => {
  try {
    const { status, page = 1, limit = 20 } = req.query;

    const where = {};
    if (status && status !== "ALL") {
      where.status = status;
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const [requests, total] = await Promise.all([
      prisma.planUpgradeRequest.findMany({
        where,
        include: {
          user: {
            select: {
              id: true,
              name: true,
              email: true,
              // Remove phone since it doesn't exist in User model
              // Use phoneNumber from PlanUpgradeRequest instead
            },
          },
        },
        orderBy: { createdAt: "desc" },
        skip,
        take: parseInt(limit),
      }),
      prisma.planUpgradeRequest.count({ where }),
    ]);

    // Get plan details for each request
    const requestsWithPlans = await Promise.all(
      requests.map(async (request) => {
        const currentPlan = await prisma.plans.findUnique({
          where: { id: request.currentPlanId },
        });

        const requestedPlan = await prisma.plans.findUnique({
          where: { id: request.requestedPlanId },
        });

        return {
          ...request,
          currentPlan,
          requestedPlan,
        };
      })
    );

    res.json({
      requests: requestsWithPlans,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit)),
      },
    });
  } catch (error) {
    console.error("Error fetching upgrade requests:", error);
    res.status(500).json({ error: error.message });
  }
});

// GET - Single upgrade request details (FIXED)
app.get("/api/admin/upgrade-requests/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const request = await prisma.planUpgradeRequest.findUnique({
      where: { id: parseInt(id) },
      include: {
        user: {
          select: {
            id: true,
            name: true,
            email: true,
            // Remove phone since it doesn't exist in User model
            createdAt: true,
          },
        },
      },
    });

    if (!request) {
      return res.status(404).json({ error: "Upgrade request not found" });
    }

    // Get plan details
    const currentPlan = await prisma.plans.findUnique({
      where: { id: request.currentPlanId },
    });

    const requestedPlan = await prisma.plans.findUnique({
      where: { id: request.requestedPlanId },
    });

    const response = {
      ...request,
      currentPlan,
      requestedPlan,
    };

    res.json(response);
  } catch (error) {
    console.error("Error fetching upgrade request:", error);
    res.status(500).json({ error: error.message });
  }
});
// Backend route - Get products by user ID
app.get("/api/users/:userId/products", async (req, res) => {
  try {
    const { userId } = req.params;

    const products = await prisma.product.findMany({
      where: {
        userId: parseInt(userId),
      },
      orderBy: {
        createdAt: "desc",
      },
      include: {
        user: {
          select: {
            name: true,
            email: true,
          },
        },
      },
    });

    res.json(products);
  } catch (error) {
    console.error("Error fetching user products:", error);
    res.status(500).json({ error: error.message });
  }
});

app.put("/api/admin/upgrade-requests/:id/status", async (req, res) => {
  try {
    const { id } = req.params;
    const { status, adminNotes } = req.body;

    if (!status || !["APPROVED", "REJECTED"].includes(status)) {
      return res
        .status(400)
        .json({ error: "Valid status (APPROVED/REJECTED) is required" });
    }

    // Get the request first
    const upgradeRequest = await prisma.planUpgradeRequest.findUnique({
      where: { id: parseInt(id) },
      include: {
        user: true,
      },
    });

    if (!upgradeRequest) {
      return res.status(404).json({ error: "Upgrade request not found" });
    }

    if (upgradeRequest.status !== "PENDING") {
      return res
        .status(400)
        .json({ error: "Request has already been processed" });
    }

    // Update the request status
    const updatedRequest = await prisma.planUpgradeRequest.update({
      where: { id: parseInt(id) },
      data: {
        status,
        adminNotes: adminNotes || null,
      },
      include: {
        user: {
          select: { id: true, name: true, email: true },
        },
      },
    });

    // If approved, update user's plan
    if (status === "APPROVED") {
      await prisma.user.update({
        where: { id: upgradeRequest.userId },
        data: { plan_id: upgradeRequest.requestedPlanId },
      });

      // Create a notification or log the upgrade
      console.log(
        `User ${upgradeRequest.userId} plan upgraded from ${upgradeRequest.currentPlanId} to ${upgradeRequest.requestedPlanId}`
      );

      // Here you can send email/notification to user about approval
    }

    // Get plan details for response
    const currentPlan = await prisma.plans.findUnique({
      where: { id: upgradeRequest.currentPlanId },
    });

    const requestedPlan = await prisma.plans.findUnique({
      where: { id: upgradeRequest.requestedPlanId },
    });

    const response = {
      ...updatedRequest,
      currentPlan,
      requestedPlan,
      message:
        status === "APPROVED"
          ? "Plan upgraded successfully"
          : "Request rejected",
    };

    res.json(response);
  } catch (error) {
    console.error("Error updating upgrade request:", error);
    res.status(400).json({ error: error.message });
  }
});

// GET - Upgrade request statistics
app.get("/api/admin/upgrade-requests/stats", async (req, res) => {
  try {
    const stats = await prisma.planUpgradeRequest.groupBy({
      by: ["status"],
      _count: {
        id: true,
      },
    });

    const total = await prisma.planUpgradeRequest.count();

    const pendingCount =
      stats.find((s) => s.status === "PENDING")?._count?.id || 0;
    const approvedCount =
      stats.find((s) => s.status === "APPROVED")?._count?.id || 0;
    const rejectedCount =
      stats.find((s) => s.status === "REJECTED")?._count?.id || 0;

    res.json({
      total,
      pending: pendingCount,
      approved: approvedCount,
      rejected: rejectedCount,
    });
  } catch (error) {
    console.error("Error fetching upgrade stats:", error);
    res.status(500).json({ error: error.message });
  }
});

// --- Get Products by User ID (Already existed implicitly, but defined here) ---
app.get("/api/users/:userId/products", async (req, res) => {
  const userId = parseInt(req.params.userId, 10);

  if (isNaN(userId)) {
    return res.status(400).json({ error: "Invalid User ID." });
  }

  // NOTE: Add Authorization check here to ensure only the owner or an admin can view this

  try {
    const products = await prisma.product.findMany({
      where: { ownerId: userId },
      // Select fields to return to minimize data transfer
      select: {
        id: true,
        name: true,
        image: true,
        status: true,
        price: true,
        inStock: true,
        rating: true,
        description: true,
      },
    });

    // You might want to process the image field here if it's stored as a comma-separated string
    const processedProducts = products.map((p) => ({
      ...p,
      // Basic image processing if needed (e.g., getting only the first image URL)
      image: p.image ? p.image.split(",")[0].trim() : null,
    }));

    res.json(processedProducts);
  } catch (error) {
    console.error("Error fetching user products:", error);
    res.status(500).json({ error: "Failed to fetch user products." });
  }
});

app.get("/api/users/:userId/businesses", async (req, res) => {
  const userId = parseInt(req.params.userId, 10);

  if (isNaN(userId)) {
    return res.status(400).json({ error: "Invalid User ID." });
  }

  // NOTE: Add Authorization check here

  try {
    const businesses = await prisma.business.findMany({
      where: { ownerId: userId },
      // Select fields to return to minimize data transfer
      select: {
        id: true,
        name: true,
        description: true,
        status: true,
        category: true,
        image: true,
      },
    });

    // You might want to process the image field here if it's stored as a comma-separated string
    const processedBusinesses = businesses.map((b) => ({
      ...b,
      image: b.image ? b.image.split(",")[0].trim() : null,
    }));

    res.json(processedBusinesses);
  } catch (error) {
    console.error("Error fetching user businesses:", error);
    res.status(500).json({ error: "Failed to fetch user businesses." });
  }
});

const PORT = process.env.PORT || 3006;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
