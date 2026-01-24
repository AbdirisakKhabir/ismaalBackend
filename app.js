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

app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password || !name) {
      return res.status(400).json({ error: "All fields are required" });
    }

    // 1. Check for existing user
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ error: "Email already registered" });
    }

    // 2. Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 3. Create the user. The 'status' field will automatically be set to 'PENDING'
    // because of the @default(PENDING) annotation in the Prisma schema.
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name,
        // No need to explicitly set status, Prisma handles the default
      },
    });

    // 4. Send response (excluding the password)
    const { password: _, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
  } catch (error) {
    console.error("Registration error:", error);
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

app.post("/api/upload", upload.array("images"), async (req, res) => {
  console.log("[UPLOAD] Receiving file(s) for Cloudinary...");
  console.log("[UPLOAD] Files received:", req.files?.length);
  console.log("[UPLOAD] Headers:", req.headers);

  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: "No image files provided" });
    }

    // Log file details for debugging
    req.files.forEach((file, index) => {
      console.log(`[UPLOAD] File ${index + 1}:`, {
        originalname: file.originalname,
        mimetype: file.mimetype,
        size: file.size,
        fieldname: file.fieldname,
      });
    });

    const uploadPromises = req.files.map((file) => {
      // Convert buffer to base64 Data URI
      const b64 = Buffer.from(file.buffer).toString("base64");
      const dataURI = "data:" + file.mimetype + ";base64," + b64;

      return cloudinary.uploader.upload(dataURI, {
        folder: "caafiCare",
        resource_type: "auto",
      });
    });

    const results = await Promise.all(uploadPromises);

    console.log(
      `[UPLOAD] Cloudinary success: ${results.length} files uploaded.`
    );

    res.json(
      results.map((result) => ({
        imageUrl: result.secure_url,
        publicId: result.public_id,
      }))
    );
  } catch (error) {
    console.error("Upload error:", error);
    res.status(500).json({
      error: error.message || "Failed to upload images to Cloudinary",
    });
  }
});

// Backend: Single Image Upload API (POST /api/upload/single)

// Multer now uses upload.single() and expects a field named "image"
app.post("/api/upload/single", upload.single("image"), async (req, res) => {
  console.log("[UPLOAD] Receiving single file for Cloudinary...");

  try {
    if (!req.file) {
      return res.status(400).json({ error: "No image file provided" });
    }

    // Log file details for debugging
    console.log(`[UPLOAD] File:`, {
      originalname: req.file.originalname,
      size: req.file.size,
    });

    // Convert buffer to base64 Data URI
    const b64 = Buffer.from(req.file.buffer).toString("base64");
    const dataURI = "data:" + req.file.mimetype + ";base64," + b64;

    const result = await cloudinary.uploader.upload(dataURI, {
      folder: "caafiCare",
      resource_type: "auto",
    });

    console.log(`[UPLOAD] Cloudinary success: 1 file uploaded.`);

    // Return a single object, not an array
    res.json({
      imageUrl: result.secure_url,
      publicId: result.public_id,
    });
  } catch (error) {
    console.error("Single Upload error:", error);
    res.status(500).json({
      error: error.message || "Failed to upload image to Cloudinary",
    });
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
// Backend endpoint for PATCH /api/users/:id
app.patch("/api/users/:id", isAuthenticated, async (req, res) => {
  try {
    const currentUserId = req.userId;
    const userIdToUpdate = req.params.id;

    console.log("=== PROFILE UPDATE ATTEMPT ===");
    console.log(
      "Current User ID from header:",
      currentUserId,
      "Type:",
      typeof currentUserId
    );
    console.log(
      "Target User ID from URL:",
      userIdToUpdate,
      "Type:",
      typeof userIdToUpdate
    );
    console.log("Update data:", req.body);

    const { name, email, phone, location, password } = req.body;

    // Convert IDs to numbers to match Prisma schema
    const currentUserIdNum = parseInt(currentUserId);
    const userIdToUpdateNum = parseInt(userIdToUpdate);

    console.log(
      "Converted Current User ID:",
      currentUserIdNum,
      "Type:",
      typeof currentUserIdNum
    );
    console.log(
      "Converted Target User ID:",
      userIdToUpdateNum,
      "Type:",
      typeof userIdToUpdateNum
    );

    if (isNaN(currentUserIdNum) || isNaN(userIdToUpdateNum)) {
      return res.status(400).json({ error: "Invalid ID format" });
    }

    // Security check: users can only update their own profile
    if (currentUserIdNum !== userIdToUpdateNum) {
      console.log("❌ Authorization mismatch:", {
        currentUser: currentUserIdNum,
        targetUser: userIdToUpdateNum,
      });
      return res
        .status(403)
        .json({ error: "Not authorized to update this profile" });
    }

    console.log(
      "✅ Authorization verified - user can update their own profile"
    );

    // 1. Find the user first
    const existingUser = await prisma.user.findUnique({
      where: { id: userIdToUpdateNum },
    });

    if (!existingUser) {
      console.log("❌ User not found with ID:", userIdToUpdateNum);
      return res.status(404).json({ error: "User not found" });
    }

    console.log("Found user:", {
      id: existingUser.id,
      email: existingUser.email,
      name: existingUser.name,
    });

    // 2. Prepare update data
    const updateData = {
      ...(name !== undefined && { name }),
      ...(email !== undefined && { email }),
      ...(phone !== undefined && { phone }),
      ...(location !== undefined && { location }),
      updatedAt: new Date(),
    };

    // Handle password hashing if provided
    if (password) {
      console.log("🔐 Password update requested");
      const hashedPassword = await bcrypt.hash(password, 10);
      updateData.password = hashedPassword;
    }

    console.log("📝 Final update data:", Object.keys(updateData));

    // 3. Perform update
    const result = await prisma.user.update({
      where: { id: userIdToUpdateNum },
      data: updateData,
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

    console.log("✅ Profile update successful:", {
      id: result.id,
      email: result.email,
      name: result.name,
    });

    res.json(result);
  } catch (error) {
    console.error("❌ PROFILE UPDATE ERROR DETAILS:");
    console.error("Error name:", error.name);
    console.error("Error code:", error.code);
    console.error("Error message:", error.message);

    if (error.code === "P2025") {
      return res.status(404).json({ error: "User not found" });
    }

    if (error.code === "P2002") {
      // Unique constraint violation (email)
      if (error.meta?.target?.includes("email")) {
        return res.status(409).json({
          error: "This email is already registered to another account.",
        });
      }
    }

    // Return the actual error message for debugging
    res.status(500).json({
      error: `Profile update failed: ${error.message}`,
    });
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
        users: {
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
    console.log(`Fetching usage data for user ${userId}`);

    // Get user with businesses and products
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        businesses: true,
        products: true,
      },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    console.log(`User found: ${user.name}, plan_id: ${user.plan_id}`);

    // CORRECTED: Get the plan using user.plan_id directly
    let activePlan = await prisma.plans.findUnique({
      where: {
        id: user.plan_id || 1, // Use user's plan_id or default to plan 1
      },
    });

    // If no plan found with plan_id, get the default plan
    if (!activePlan) {
      console.log(`No plan found with id ${user.plan_id}, using default plan`);
      activePlan = await prisma.plans.findUnique({
        where: { id: 1 }, // Default plan ID
      });
    }

    if (!activePlan) {
      return res.status(400).json({ error: "No plan configuration found" });
    }

    console.log(
      `Active plan: ${activePlan.name}, allowed businesses: ${activePlan.allowedBusinesses}, allowed products: ${activePlan.allowedProducts}`
    );

    // Count only ACTIVE or APPROVED businesses/products
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

    console.log(`Usage data for user ${userId}:`, {
      businesses: `${usage.businesses.count}/${usage.businesses.limit}`,
      products: `${usage.products.count}/${usage.products.limit}`,
    });

    res.json(usage);
  } catch (error) {
    console.error("Error fetching user usage:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/businesses", async (req, res) => {
  try {
    // 1. Run the updated server-side validation
    const validationError = validateBusinessData(req.body);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    const {
      name,
      description,
      category,
      phone,
      email,
      location,
      image, // This should be a comma-separated string of URLs
      ownerId,
      businessType = "GENERAL",
    } = req.body;

    // 2. Limit Check Logic
    const user = await prisma.user.findUnique({
      where: { id: ownerId },
      include: {
        plan: true,
        businesses: {
          where: {
            status: "APPROVED",
          },
        },
      },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Get the user's plan - it's an array
    let userPlan;
    if (user.plan && user.plan.length > 0) {
      userPlan = user.plan[0];
    } else {
      userPlan = await prisma.plans.findUnique({
        where: { id: user.plan_id || 1 },
      });
    }

    if (!userPlan) {
      return res.status(400).json({ error: "No active plan found" });
    }

    const businessLimit = userPlan.allowedBusinesses;
    const currentBusinessCount = user.businesses.length;

    if (currentBusinessCount >= businessLimit) {
      return res.status(403).json({
        error: `Business limit reached. You can only create ${businessLimit} business(es) with your ${userPlan.name}.`,
        code: "BUSINESS_LIMIT_REACHED",
        currentCount: currentBusinessCount,
        limit: businessLimit,
      });
    }

    // 3. Create Business with comma-separated image string
    const business = await prisma.business.create({
      data: {
        name,
        description,
        category,
        phone,
        email,
        location,
        image: image, // Store as comma-separated string
        ownerId,
        status: "PENDING",
        businessType,
      },
      include: {
        owner: {
          select: {
            id: true,
            name: true,
            email: true,
          },
        },
      },
    });

    res.json({
      success: true,
      business,
      message: "Business submitted for approval",
      limits: {
        currentCount: currentBusinessCount + 1,
        limit: businessLimit,
        remaining: businessLimit - (currentBusinessCount + 1),
      },
    });
  } catch (error) {
    console.error("Error creating business:", error);
    res.status(400).json({
      error: error.message || "Failed to create business",
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

const validateProductData = (data) => {
  const errors = {};

  if (!data.name?.trim()) errors.name = "Product name is required.";
  if (!data.description?.trim() || data.description.length < 15) {
    errors.description = "Description must be at least 15 characters.";
  }

  // --- Price Validation ---
  const priceValue = parseFloat(data.price);
  const priceToValue = parseFloat(data.price_to);
  const crossedPriceValue = parseFloat(data.crossed_price);

  if (data.price_option === "Fixed" || data.price_option === "Crossed") {
    if (!data.price || isNaN(priceValue) || priceValue <= 0) {
      errors.price = "A valid fixed price is required.";
    }
  } else if (data.price_option === "Range") {
    if (!data.price || isNaN(priceValue) || priceValue <= 0) {
      errors.price = "A valid 'Price From' is required.";
    }
    if (
      !data.price_to ||
      isNaN(priceToValue) ||
      priceToValue <= 0 ||
      priceToValue < priceValue
    ) {
      errors.price_to =
        "A valid 'Price To' is required and must be greater than Price From.";
    }
  } else if (data.price_option === "Negotiable") {
    // Price is optional, but if provided, must be valid
    if (data.price && (isNaN(priceValue) || priceValue <= 0)) {
      errors.price = "If providing a price, it must be valid.";
    }
  }

  if (data.price_option === "Crossed") {
    if (
      !data.crossed_price ||
      isNaN(crossedPriceValue) ||
      crossedPriceValue <= priceValue
    ) {
      errors.crossed_price =
        "Original price (crossed) is required and must be higher than the new price.";
    }
  }

  // --- Other Validations ---
  if (data.category.length === 0)
    errors.category = "At least one category is required.";
  if (!data.type?.trim()) errors.type = "Product condition (type) is required.";
  if (!data.location?.trim()) errors.location = "Location is required.";
  if (data.image.length === 0)
    errors.image = "At least one product image is required.";
  if (!data.posted_from?.trim())
    errors.posted_from = "Posting source is required.";

  return Object.keys(errors).length > 0 ? errors : null;
};

app.post("/api/products", async (req, res) => {
  try {
    const {
      userId,
      name,
      description,
      price,
      price_to,
      price_option,
      crossed_price,
      category,
      type,
      location,
      posted_from, // This should be a string like "Personal Account" or "Business: Business Name"
      posted_from_id, // This is the numeric ID
      image,
      status = "PENDING",
    } = req.body;

    // Validation
    const validationError = validateProductData(req.body);
    if (validationError) {
      return res.status(400).json({ error: validationError });
    }

    // Check if user exists
    const user = await prisma.user.findUnique({
      where: { id: parseInt(userId) },
      include: {
        plan: true,
        products: {
          where: { status: "ACTIVE" },
        },
      },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Get the user's plan - it's an array
    let userPlan;
    if (user.plan && user.plan.length > 0) {
      userPlan = user.plan[0];
    } else {
      userPlan = await prisma.plans.findUnique({
        where: { id: user.plan_id || 1 },
      });
    }

    if (!userPlan) {
      return res.status(400).json({ error: "User has no active plan" });
    }

    // Check product limit
    const productLimit = userPlan.allowedProducts;
    const currentProductCount = user.products.length;

    if (currentProductCount >= productLimit) {
      return res.status(403).json({
        error: `Product limit reached. You can only create ${productLimit} product(s) with your ${userPlan.name} plan.`,
        code: "PRODUCT_LIMIT_REACHED",
        currentCount: currentProductCount,
        limit: productLimit,
      });
    }

    // Make sure posted_from is a string
    let postedFromString = posted_from;
    if (typeof postedFromString !== "string") {
      // If posted_from is not a string, convert it
      postedFromString = String(postedFromString || "Personal Account");
    }

    // Create product data
    const productData = {
      name,
      description,
      price: parseFloat(price || 0),
      price_option,
      crossed_price: crossed_price ? parseFloat(crossed_price) : null,
      category,
      type,
      location,
      posted_from: postedFromString, // Must be a string
      image,
      userId: parseInt(userId),
      status,
    };

    // Only include price_to if it has a value
    if (price_to !== undefined && price_to !== null && price_to !== "") {
      productData.price_to = parseFloat(price_to);
    }

    console.log("Creating product with data:", productData);

    // Create product
    const product = await prisma.product.create({
      data: productData,
    });

    res.json({
      success: true,
      product,
      message: "Product submitted successfully for approval",
      limits: {
        currentCount: currentProductCount + 1,
        limit: productLimit,
        remaining: productLimit - (currentProductCount + 1),
      },
    });
  } catch (error) {
    console.error("Error creating product:", error);
    res.status(500).json({
      error: error.message || "Failed to create product",
    });
  }
});

app.get("/api/products", async (req, res) => {
  try {
    const products = await prisma.product.findMany({
      where: { status: "APPROVED" },
    });

    const processedProducts = products.map(processProductData);

    res.json(processedProducts);
  } catch (error) {
    console.error("Error fetching products:", error);
    res.status(400).json({ error: error.message });
  }
});

app.patch("/api/businesses/:id", isAuthenticated, async (req, res) => {
  try {
    const currentUserId = req.userId; // This comes as string "6" from header
    const businessId = req.params.id; // This comes as string "8" from URL

    console.log("=== UPDATE ATTEMPT ===");
    console.log(
      "User ID from header:",
      currentUserId,
      "Type:",
      typeof currentUserId
    );
    console.log(
      "Business ID from URL:",
      businessId,
      "Type:",
      typeof businessId
    );
    console.log("Update data:", req.body);

    const { name, description, category, phone, email, location } = req.body;

    // Convert IDs to numbers to match Prisma schema
    const currentUserIdNum = parseInt(currentUserId);
    const businessIdNum = parseInt(businessId);

    console.log(
      "Converted User ID:",
      currentUserIdNum,
      "Type:",
      typeof currentUserIdNum
    );
    console.log(
      "Converted Business ID:",
      businessIdNum,
      "Type:",
      typeof businessIdNum
    );

    if (isNaN(currentUserIdNum) || isNaN(businessIdNum)) {
      return res.status(400).json({ error: "Invalid ID format" });
    }

    // 1. Find the business first
    const business = await prisma.business.findUnique({
      where: { id: businessIdNum },
    });

    if (!business) {
      console.log("❌ Business not found with ID:", businessIdNum);
      return res.status(404).json({ error: "Business not found" });
    }

    console.log("Found business:", {
      id: business.id,
      ownerId: business.ownerId,
      name: business.name,
    });

    // 2. Check ownership (compare numbers)
    if (business.ownerId !== currentUserIdNum) {
      console.log("❌ Ownership mismatch:", {
        businessOwner: business.ownerId,
        currentUser: currentUserIdNum,
      });
      return res
        .status(403)
        .json({ error: "Not authorized to update this business" });
    }

    console.log("✅ Ownership verified - user owns this business");

    // 3. Prepare update data
    const updateData = {
      name: name || business.name,
      description: description || business.description,
      category: category || business.category,
      phone: phone || business.phone,
      email: email || business.email,
      location: location || business.location,
      status: "PENDING", // Reset to pending for admin review
      updatedAt: new Date(),
    };

    console.log("📝 Final update data:", updateData);

    // 4. Perform update
    const result = await prisma.business.update({
      where: { id: businessIdNum },
      data: updateData,
    });

    console.log("✅ Update successful:", {
      id: result.id,
      name: result.name,
      status: result.status,
    });

    res.json({
      message: "Business updated successfully and set to PENDING for review",
      business: result,
    });
  } catch (error) {
    console.error("❌ UPDATE ERROR DETAILS:");
    console.error("Error name:", error.name);
    console.error("Error code:", error.code);
    console.error("Error message:", error.message);

    if (error.code === "P2025") {
      return res.status(404).json({ error: "Business not found" });
    }

    if (error.code === "P2002") {
      return res
        .status(409)
        .json({ error: "A business with this name or email already exists" });
    }

    // Return the actual error message for debugging
    res.status(500).json({
      error: `Update failed: ${error.message}`,
    });
  }
});

// Backend endpoint for PATCH /api/products/:id
app.patch("/api/products/:id", isAuthenticated, async (req, res) => {
  try {
    const currentUserId = req.userId;
    const productId = req.params.id;

    console.log("=== PRODUCT UPDATE ATTEMPT ===");
    console.log(
      "User ID from header:",
      currentUserId,
      "Type:",
      typeof currentUserId
    );
    console.log("Product ID from URL:", productId, "Type:", typeof productId);
    console.log("Update data:", req.body);

    const { name, description, price, category, location } = req.body;

    // Convert IDs to numbers to match Prisma schema
    const currentUserIdNum = parseInt(currentUserId);
    const productIdNum = parseInt(productId);

    console.log(
      "Converted User ID:",
      currentUserIdNum,
      "Type:",
      typeof currentUserIdNum
    );
    console.log(
      "Converted Product ID:",
      productIdNum,
      "Type:",
      typeof productIdNum
    );

    if (isNaN(currentUserIdNum) || isNaN(productIdNum)) {
      return res.status(400).json({ error: "Invalid ID format" });
    }

    // 1. Find the product first
    const existingProduct = await prisma.product.findUnique({
      where: { id: productIdNum },
    });

    if (!existingProduct) {
      console.log("❌ Product not found with ID:", productIdNum);
      return res.status(404).json({ error: "Product not found" });
    }

    console.log("Found product:", {
      id: existingProduct.id,
      userId: existingProduct.userId,
      name: existingProduct.name,
    });

    // 2. Check ownership (compare numbers)
    if (existingProduct.userId !== currentUserIdNum) {
      console.log("❌ Ownership mismatch:", {
        productOwner: existingProduct.userId,
        currentUser: currentUserIdNum,
      });
      return res
        .status(403)
        .json({ error: "Not authorized to update this product" });
    }

    console.log("✅ Ownership verified - user owns this product");

    // 3. Prepare update data
    const updateData = {
      name: name || existingProduct.name,
      description: description || existingProduct.description,
      price: price || existingProduct.price,
      category: category || existingProduct.category,
      location: location || existingProduct.location,
      status: "PENDING", // Reset to pending for admin review
      updatedAt: new Date(),
    };

    console.log("📝 Final update data:", updateData);

    // 4. Perform update
    const result = await prisma.product.update({
      where: { id: productIdNum },
      data: updateData,
    });

    console.log("✅ Product update successful:", {
      id: result.id,
      name: result.name,
      status: result.status,
    });

    res.json({
      message: "Product updated successfully and set to PENDING for review",
      product: result,
    });
  } catch (error) {
    console.error("❌ PRODUCT UPDATE ERROR DETAILS:");
    console.error("Error name:", error.name);
    console.error("Error code:", error.code);
    console.error("Error message:", error.message);

    if (error.code === "P2025") {
      return res.status(404).json({ error: "Product not found" });
    }

    if (error.code === "P2002") {
      return res
        .status(409)
        .json({ error: "A product with this name already exists" });
    }

    // Return the actual error message for debugging
    res.status(500).json({
      error: `Product update failed: ${error.message}`,
    });
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
  const errors = {};

  if (data.profession.length === 0) {
    errors.profession = "At least one profession is required";
  } else if (data.profession.length > 5) {
    errors.profession = "Maximum 5 professions allowed";
  }

  if (!data.specialty?.trim()) {
    errors.specialty = "Specialty/Education level is required";
  }

  if (!data.experience?.trim()) {
    errors.experience = "Experience level is required";
  }

  if (!data.location?.trim()) {
    errors.location = "Location is required";
  }

  if (!data.phone?.trim()) {
    errors.phone = "Phone number is required";
  } else if (!/^\d{5,15}$/.test(data.phone)) {
    errors.phone = "Please enter a valid phone number (digits only)";
  }

  if (!data.email?.trim()) {
    errors.email = "Email is required";
  } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email)) {
    errors.email = "Please enter a valid email address";
  }

  // Optional: Add description validation if needed
  if (data.description && data.description.length > 1000) {
    errors.description = "Description must be 1000 characters or less";
  }

  return Object.keys(errors).length > 0 ? errors : null;
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




app.delete("/api/businesses/:id", async (req, res) => {
  try {
    const numericId = parseInt(req.params.id, 10);

    if (isNaN(numericId)) {
      return res.status(400).json({ error: "Invalid business ID" });
    }

    const deletedBusiness = await prisma.business.delete({
      where: { id: numericId },
    });

    return res.json({
      message: "Business deleted successfully",
      business: deletedBusiness,
    });
  } catch (error) {
    console.error("Error deleting business:", error);

    if (error.code === "P2025") {
      return res.status(404).json({ error: "Business not found" });
    }

    return res.status(500).json({ error: "Failed to delete business" });
  }
});

app.get("/api/entity/:type/:id/products", async (req, res) => {
  try {
    const { id, type } = req.params;
    let ownerId;
    let entityName;

    // 1. Determine the ownerId based on the entity type
    if (type === "business") {
      const business = await prisma.business.findUnique({
        where: { id: parseInt(id) },
      });

      if (!business) {
        return res.status(404).json({ error: "Business not found" });
      }
      ownerId = business.ownerId; // Assuming Business has ownerId
      entityName = business.name;
    } else if (type === "professional") {
      const professional = await prisma.professional.findUnique({
        where: { id: parseInt(id) },
      });

      if (!professional) {
        return res.status(404).json({ error: "Professional not found" });
      }
      ownerId = professional.userId; // Assuming Professional has userId (the owner)
      entityName = professional.specialty; // Use specialty or profession as the name
    } else {
      return res.status(400).json({ error: "Invalid entity type specified" });
    }

    // Check if ownerId was successfully found
    if (!ownerId) {
      console.error(`[PRODUCTS] Owner ID not found for ${type} ${id}`);
      return res
        .status(404)
        .json({ error: `Owner not linked to this ${type}` });
    }

    // 2. Get products by the entity owner
    const products = await prisma.product.findMany({
      where: {
        userId: ownerId, // Fetch products linked to the owner's ID
        status: "APPROVED", // Only show approved products
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    console.log(
      `[PRODUCTS] Found ${products.length} products for ${entityName} (${type} ${id})`
    );
    res.json(products);
  } catch (error) {
    console.error("Error fetching entity products:", error);
    res.status(500).json({ error: "Failed to fetch entity products" });
  }
});

// GET /api/professionals/user/:userId?status=APPROVED
app.get("/api/professionals/user/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const { status } = req.query;

    const whereClause = {
      userId: parseInt(userId),
    };

    // Add status filter if provided
    if (status) {
      whereClause.status = status.toUpperCase();
    }

    const professionals = await prisma.professional.findMany({
      where: whereClause,
      select: {
        id: true,
        profession: true,
        specialty: true,
        experience: true,
        location: true,
        status: true,
        createdAt: true,
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    res.json(professionals);
  } catch (error) {
    console.error("Error fetching user professionals:", error);
    res.status(500).json({ error: "Failed to fetch professionals" });
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
      // 🔑 ADDED: Include the related 'user' data
      include: {
        user: {
          select: {
            id: true,
            name: true, // Fetch the user's name
            email: true, // Fetch the user's email
            // Note: If 'phone' is on the User model, include it here.
            // Since it's not in the provided User model, we'll assume it's fetched from the User model if available.
          },
        },
      },
    });

    if (!product) {
      return res.status(404).json({ error: "Product not found" });
    }

    // 💡 OPTIONAL: Flatten the data for easier use on the frontend
    const formattedProduct = {
      ...product,
      userName: product.user.name,
      userEmail: product.user.email,
      // userPhone: product.user.phone, // Include if phone is on the User model
    };

    // Remove the nested user object if you flattened it
    delete formattedProduct.user;

    res.json(formattedProduct); // Send the formatted product
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

app.get("/api/professionals/approved", async (req, res) => {
  try {
    // 💡 FIX 1: Query the 'professional' model, not the 'user' model.
    const approvedProfessionals = await prisma.professional.findMany({
      // 💡 FIX 2: Filter by status on the Professional model.
      // Assuming APPROVED is the correct status value based on the request logic.
      where: { status: "APPROVED" },

      // 💡 FIX 3: Include the related 'user' data for name/email.
      include: {
        user: { select: { id: true, name: true, email: true } },
      },
      orderBy: { submittedDate: "desc" },
    });

    const formattedProfessionals = approvedProfessionals.map(
      (professional) => ({
        id: professional.id,
        userId: professional.userId,
        // The user data is now accessed correctly through the included 'user' object
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
    // You can log the full error for better debugging in the console
    // console.error(error);
    res.status(500).json({ error: "Failed to fetch approved professionals" });
  }
});

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

// Replace your current upgrade-requests endpoint with this:
app.post("/api/verify-purchase", async (req, res) => {
  try {
    const { userId, planId, receiptData, transactionId } = req.body;

    // Validate required fields
    if (!userId || !planId || !receiptData || !transactionId) {
      return res.status(400).json({ error: "All fields are required" });
    }

    // Verify receipt with Apple's servers
    const verificationResult = await verifyAppleReceipt(receiptData);

    if (verificationResult.valid) {
      // Check if this transaction was already processed (prevent duplicate upgrades)
      const existingTransaction = await prisma.transaction.findUnique({
        where: { transactionId: transactionId },
      });

      if (existingTransaction) {
        return res.status(400).json({
          error: "This transaction was already processed",
          transaction: existingTransaction,
        });
      }

      // Update user's plan immediately
      const updatedUser = await prisma.user.update({
        where: { id: parseInt(userId) },
        data: {
          planId: parseInt(planId),
          updatedAt: new Date(),
        },
        include: {
          plan: true,
        },
      });

      // Record the successful transaction
      const transaction = await prisma.transaction.create({
        data: {
          userId: parseInt(userId),
          planId: parseInt(planId),
          transactionId: transactionId,
          productId: verificationResult.productId,
          amount: verificationResult.amount,
          status: "COMPLETED",
          paymentMethod: "APPLE_IAP",
          purchaseDate: verificationResult.purchaseDate || new Date(),
        },
        include: {
          user: {
            select: {
              id: true,
              name: true,
              email: true,
              plan: true,
            },
          },
          plan: true,
        },
      });

      // Optional: Send confirmation email or notification
      await sendUpgradeConfirmation(updatedUser, transaction);

      res.json({
        success: true,
        message: "Purchase verified and plan upgraded successfully",
        user: updatedUser,
        transaction: transaction,
      });
    } else {
      res.status(400).json({
        error: "Invalid receipt - purchase verification failed",
        appleError: verificationResult.error,
      });
    }
  } catch (error) {
    console.error("Purchase verification error:", error);
    res.status(500).json({ error: "Failed to verify purchase" });
  }
});

// Enhanced Apple receipt verification
async function verifyAppleReceipt(receiptData) {
  try {
    const verificationUrl =
      process.env.NODE_ENV === "production"
        ? "https://buy.itunes.apple.com/verifyReceipt"
        : "https://sandbox.itunes.apple.com/verifyReceipt";

    const response = await fetch(verificationUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        "receipt-data": receiptData,
        password: process.env.APPLE_SHARED_SECRET,
        "exclude-old-transactions": false,
      }),
    });

    const result = await response.json();

    if (result.status === 0) {
      // 0 = success
      const latestReceipt =
        result.latest_receipt_info?.[0] || result.receipt?.in_app?.[0];

      if (!latestReceipt) {
        return { valid: false, error: "No receipt info found" };
      }

      return {
        valid: true,
        amount: parseFloat(latestReceipt.price) || 0,
        productId: latestReceipt.product_id,
        purchaseDate: latestReceipt.purchase_date_ms
          ? new Date(parseInt(latestReceipt.purchase_date_ms))
          : new Date(),
      };
    } else {
      console.log("Apple verification failed with status:", result.status);
      return {
        valid: false,
        error: `Apple verification failed with status: ${result.status}`,
      };
    }
  } catch (error) {
    console.error("Apple verification error:", error);
    return {
      valid: false,
      error: `Verification failed: ${error.message}`,
    };
  }
}

// Optional: Helper function for confirmation email
async function sendUpgradeConfirmation(user, transaction) {
  try {
    // Implement your email service here (SendGrid, AWS SES, etc.)
    console.log(
      `Upgrade confirmation sent to ${user.email} for plan ${transaction.plan.name}`
    );
  } catch (error) {
    console.error("Failed to send upgrade confirmation:", error);
  }
}

// Helper function to verify with Apple
async function verifyAppleReceipt(receiptData) {
  try {
    const verificationUrl =
      process.env.NODE_ENV === "production"
        ? "https://buy.itunes.apple.com/verifyReceipt"
        : "https://sandbox.itunes.apple.com/verifyReceipt";

    const response = await fetch(verificationUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        "receipt-data": receiptData,
        password: process.env.APPLE_SHARED_SECRET, // From App Store Connect
        "exclude-old-transactions": false,
      }),
    });

    const result = await response.json();

    if (result.status === 0) {
      // 0 = success
      const latestReceipt = result.latest_receipt_info[0];
      return {
        valid: true,
        amount: parseFloat(latestReceipt.price),
        productId: latestReceipt.product_id,
        purchaseDate: new Date(parseInt(latestReceipt.purchase_date_ms)),
      };
    } else {
      console.log("Apple verification failed with status:", result.status);
      return { valid: false, error: result.status };
    }
  } catch (error) {
    console.error("Apple verification error:", error);
    return { valid: false, error: "Verification failed" };
  }
}

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
        email: true,
        phone: true,
        location: true,
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

app.get("/api/professionals/approved", async (req, res) => {
  try {
    const approvedProfessionals = await prisma.professional.findMany({
      // Assuming 'submittedDate' is a field on the Professional model
      orderBy: { submittedDate: "desc" },
    });

    const formattedProfessionals = approvedProfessionals.map(
      (professional) => ({
        id: professional.id,
        userId: professional.userId,
        // Accessing the name/email from the included 'user' object
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

// NEW ROUTE: Count the number of Professional profiles for a specific user
app.get("/api/users/:userId/profiles/count", async (req, res) => {
  const userId = parseInt(req.params.userId, 10);

  if (isNaN(userId)) {
    return res.status(400).json({ error: "Invalid User ID." });
  }

  // NOTE: Add Authorization check here

  try {
    // Use prisma.professional.count() to efficiently get the number of records
    const profileCount = await prisma.professional.count({
      where: { userId: userId },
    });

    // Return the count directly
    res.json({ count: profileCount });
  } catch (error) {
    console.error("Error fetching user professional count:", error);
    res.status(500).json({ error: "Failed to fetch user professional count." });
  }
});

app.get("/api/users/:userId/profiles", async (req, res) => {
  const userId = parseInt(req.params.userId, 10);

  if (isNaN(userId)) {
    return res.status(400).json({ error: "Invalid User ID." });
  }

  // NOTE: Add Authorization check here

  try {
    const businesses = await prisma.professional.findMany({
      where: { ownerId: userId },
      // Select fields to return to minimize data transfer
      select: {
        id: true,
        name: true,
        email: true,
        phone: true,
        location: true,
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

app.get("/api/businesses/user/:userId", async (req, res) => {
  try {
    const { userId } = req.params;
    const { status } = req.query;

    const whereClause = {
      ownerId: parseInt(userId),
    };

    // Add status filter if provided
    if (status) {
      whereClause.status = status.toUpperCase();
    }

    const businesses = await prisma.business.findMany({
      where: whereClause,
      select: {
        id: true,
        name: true,
        category: true,
        location: true,
        status: true,
        createdAt: true,
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    res.json(businesses);
  } catch (error) {
    console.error("Error fetching user businesses:", error);
    res.status(500).json({ error: "Failed to fetch businesses" });
  }
});

const PORT = process.env.PORT || 3006;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
