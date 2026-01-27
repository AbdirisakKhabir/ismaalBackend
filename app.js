const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { verifyToken } = require("./middleware/auth.ts");
const messagingService = require("./services/messagingServices");
// Load environment variables

dotenv.config();

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3005;
const JWT_SECRET =
  process.env.JWT_SECRET ||
  "blood-donation-app-secure-fallback-key-2024-must-be-changed";

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || "fallback-secret"
    );

    // Check if user exists and is active
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: { id: true, email: true, isActive: true },
    });

    if (!user || !user.isActive) {
      return res.status(401).json({ error: "User not found or inactive" });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ error: "Invalid token" });
  }
};

const authenticateAdmin = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || "fallback-secret"
    );

    // Check if admin exists and is active
    const admin = await prisma.admin.findUnique({
      where: { id: decoded.adminId },
      select: { id: true, email: true, isActive: true, role: true },
    });

    if (!admin || !admin.isActive) {
      return res.status(401).json({ error: "Admin not found or inactive" });
    }

    req.admin = admin;
    next();
  } catch (error) {
    return res.status(403).json({ error: "Invalid token" });
  }
};

// ========================================
// AUTHENTICATION ROUTES
// ========================================

// User Registration
app.post("/api/auth/register/user", async (req, res) => {
  try {
    const {
      password,
      fullName,
      phone,
      gender,
      age,
      location,
      bloodType,
      role,
    } = req.body;

    // Validation
    if (
      !password ||
      !fullName ||
      !phone ||
      !gender ||
      !age ||
      !location ||
      !bloodType
    ) {
      return res.status(400).json({ error: "All fields are required" });
    }

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { phone },
    });

    if (existingUser) {
      return res
        .status(400)
        .json({ error: "Akoonka hore waa uu jiraa, fadlan gali akoon sax ah" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Determine if user should be admin (you can add your logic here)
    const userRole = role || "USER"; // Default to USER if no role provided

    // Create user
    const user = await prisma.user.create({
      data: {
        password: hashedPassword,
        fullName,
        phone,
        gender,
        age: parseInt(age),
        location,
        bloodType,
        role: userRole, // Add role field
      },
      select: {
        id: true,
        fullName: true,
        phone: true,
        gender: true,
        age: true,
        location: true,
        bloodType: true,
        role: true, // Include role in response
        isActive: true,
        isEligible: true,
        totalDonations: true,
        createdAt: true,
      },
    });

    // Generate JWT token with role
    const token = jwt.sign(
      {
        userId: user.id,
        phone: user.phone,
        role: user.role, // Include role in JWT
      },
      process.env.JWT_SECRET || "fallback-secret",
      { expiresIn: "7d" }
    );

    res.status(201).json({
      message: "User registered successfully",
      user,
      token,
    });
  } catch (error) {
    console.error("User registration error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Admin Registration API
app.post("/api/auth/register/admin", async (req, res) => {
  try {
    const {
      email,
      password,
      fullName,
      phone,
      organization,
      position,
      department,
      role,
      isRequestApproved,
    } = req.body;

    // Validation
    if (
      !email ||
      !password ||
      !fullName ||
      !phone ||
      !organization ||
      !position ||
      !role
    ) {
      return res
        .status(400)
        .json({ error: "Goobaha loo baahan yahay waa laga maarmay" });
    }

    // Validate role
    const validRoles = ["ADMIN", "SENDER"];
    if (!validRoles.includes(role)) {
      return res.status(400).json({ error: "Doorku waa khalad" });
    }

    // Check if admin already exists
    const existingAdmin = await prisma.admin.findUnique({
      where: { email },
    });

    if (existingAdmin) {
      return res.status(400).json({ error: "Admin hore u jiray" });
    }

    // Check if phone already exists
    const existingPhone = await prisma.admin.findFirst({
      where: { phone },
    });

    if (existingPhone) {
      return res
        .status(400)
        .json({ error: "Lambarka taleefanka hore u jiray" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create admin
    const admin = await prisma.admin.create({
      data: {
        email,
        password: hashedPassword,
        fullName,
        phone,
        organization,
        position,
        department: department || null,
        role,
        isRequestApproved: isRequestApproved || false,
        isActive: true,
      },
      select: {
        id: true,
        email: true,
        fullName: true,
        phone: true,
        organization: true,
        position: true,
        department: true,
        role: true,
        isRequestApproved: true,
        isActive: true,
        createdAt: true,
      },
    });

    // Generate JWT token
    const token = jwt.sign(
      { adminId: admin.id, email: admin.email, role: admin.role },
      process.env.JWT_SECRET || "fallback-secret",
      { expiresIn: "7d" }
    );

    res.status(201).json({
      message: "Admin si guul leh ayaa loo diiwaangaliyay",
      admin,
      token,
    });
  } catch (error) {
    console.error("Admin registration error:", error);
    res.status(500).json({ error: "Khalad server dhexdii saaran" });
  }
});

// User Login
// At the top of your auth file, define a secure fallback
app.post("/api/auth/login/user", async (req, res) => {
  try {
    const { phone, password } = req.body;

    if (!phone || !password) {
      return res.status(400).json({ error: "Phone and password required" });
    }

    // Find user
    const user = await prisma.user.findUnique({
      where: { phone },
    });

    if (!user || !user.isActive) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Generate JWT token with proper secret
    const token = jwt.sign(
      {
        userId: user.id,
        phone: user.phone,
      },
      process.env.JWT_SECRET, // Use from environment
      { expiresIn: "7d" } // 7 days
    );

    // Remove password from response
    const { password: _, ...userData } = user;

    res.json({
      message: "Login successful",
      user: userData,
      token,
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Admin Login
app.post("/api/auth/login/admin", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" });
    }

    // Find admin
    const admin = await prisma.admin.findUnique({
      where: { email },
    });

    if (!admin || !admin.isActive) {
      return res
        .status(401)
        .json({ error: "Invalid credentials or admin inactive" });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, admin.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Generate JWT token
    const token = jwt.sign(
      { adminId: admin.id, email: admin.email },
      process.env.JWT_SECRET || "fallback-secret",
      { expiresIn: "7d" }
    );

    // Return admin data (without password)
    const { password: _, ...adminData } = admin;

    res.json({
      message: "Login successful",
      admin: adminData,
      token,
    });
  } catch (error) {
    console.error("Admin login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Delete User Account Permanently (No password required, only userId)
app.delete("/api/auth/account", async (req, res) => {
  try {
    const { userId } = req.body;

    // Validate userId is provided
    if (!userId) {
      return res.status(400).json({
        success: false,
        error: "User ID is required",
      });
    }

    // Parse and validate userId is a valid integer
    const userIdInt = parseInt(userId);
    if (isNaN(userIdInt) || userIdInt <= 0) {
      return res.status(400).json({
        success: false,
        error: "Invalid user ID format",
      });
    }

    // Find the user first to check if they exist
    const user = await prisma.user.findUnique({
      where: { id: userIdInt },
      select: {
        id: true,
        fullName: true,
        email: true,
        phone: true,
        role: true,
      },
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    // Prevent deletion of admin users (safety check)
    if (user.role === "ADMIN") {
      return res.status(403).json({
        success: false,
        error: "Cannot delete admin users",
      });
    }

    console.log(`🗑️  Starting deletion process for user ID: ${userIdInt} (${user.fullName})`);

    // Start a transaction to delete all related data atomically
    await prisma.$transaction(async (tx) => {
      // Delete user's sessions/tokens if they exist
      try {
        const deletedSessions = await tx.session.deleteMany({
          where: { userId: userIdInt },
        });
        console.log(`✅ Deleted ${deletedSessions.count} session(s)`);
      } catch (e) {
        // Session table might not exist, ignore error
        console.log(`ℹ️  Sessions table not found or already deleted`);
      }

      // Delete user's blood requests
      try {
        const deletedRequests = await tx.bloodRequest.deleteMany({
          where: { userId: userIdInt },
        });
        console.log(`✅ Deleted ${deletedRequests.count} blood request(s)`);
      } catch (e) {
        console.log(`ℹ️  Blood requests not found or already deleted`);
      }

      // Delete user's donations (as donor)
      try {
        const deletedDonations = await tx.donation.deleteMany({
          where: { donorId: userIdInt },
        });
        console.log(`✅ Deleted ${deletedDonations.count} donation(s)`);
      } catch (e) {
        console.log(`ℹ️  Donations not found or already deleted`);
      }

      // Delete user's notifications
      try {
        const deletedNotifications = await tx.userNotification.deleteMany({
          where: { userId: userIdInt },
        });
        console.log(`✅ Deleted ${deletedNotifications.count} notification(s)`);
      } catch (e) {
        console.log(`ℹ️  Notifications not found or already deleted`);
      }

      // Delete user's history if exists
      try {
        const deletedHistory = await tx.userHistory.deleteMany({
          where: { userId: userIdInt },
        });
        console.log(`✅ Deleted ${deletedHistory.count} history record(s)`);
      } catch (e) {
        console.log(`ℹ️  User history not found or already deleted`);
      }

      // Finally delete the user
      await tx.user.delete({
        where: { id: userIdInt },
      });
      console.log(`✅ User deleted successfully`);
    });

    console.log(`✅ Account deletion completed for user ID: ${userIdInt}`);

    res.json({
      success: true,
      message: "Account deleted permanently",
      deletedUser: {
        id: user.id,
        name: user.fullName,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("❌ Error deleting account:", error);

    // Handle Prisma specific errors
    if (error.code === "P2025") {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    // Handle foreign key constraint errors
    if (error.code === "P2003") {
      return res.status(400).json({
        success: false,
        error: "Cannot delete user due to existing relationships",
        details: "Please remove all related data first",
      });
    }

    res.status(500).json({
      success: false,
      error: "Failed to delete account",
      details: error.message,
    });
  }
});

// Find user by phone number
app.post("/api/users/find-by-phone", async (req, res) => {
  try {
    const { phone } = req.body;

    if (!phone) {
      return res
        .status(400)
        .json({ error: "Lambarka taleefanka waa loo baahan yahay" });
    }

    // Now using findUnique since phone is unique
    const user = await prisma.user.findUnique({
      where: {
        phone: phone,
      },
      select: {
        id: true,
        phone: true,
        fullName: true,
        gender: true,
        age: true,
        location: true,
        bloodType: true,
        isActive: true,
        isEligible: true,
        totalDonations: true,
        lastDonation: true,
        createdAt: true,
      },
    });

    if (!user) {
      return res.status(404).json({ error: "Isticmaale lambarkan ma helin" });
    }

    if (!user.isActive) {
      return res.status(401).json({ error: "Akoonkan waa mamnuuc" });
    }

    res.json({
      message: "Isticmaale la helay",
      user: user,
    });
  } catch (error) {
    console.error("Find user error:", error);
    res.status(500).json({ error: "Khalad server dhexdii saaran" });
  }
});

// ========================================
// USER ROUTES
// ========================================

// Get User Profile
app.get("/api/users/profile", authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: {
        id: true,
        email: true,
        fullName: true,
        phone: true,
        gender: true,
        age: true,
        location: true,
        bloodType: true,
        isActive: true,
        isEligible: true,
        totalDonations: true,
        lastDonation: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({ user });
  } catch (error) {
    console.error("Get profile error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Update User Profile
app.put("/api/users/profile", authenticateToken, async (req, res) => {
  try {
    const { fullName, phone, age, location, bloodType } = req.body;

    const updatedUser = await prisma.user.update({
      where: { id: req.user.id },
      data: {
        fullName: fullName || undefined,
        phone: phone || undefined,
        age: age ? parseInt(age) : undefined,
        location: location || undefined,
        bloodType: bloodType || undefined,
      },
      select: {
        id: true,
        email: true,
        fullName: true,
        phone: true,
        gender: true,
        age: true,
        location: true,
        bloodType: true,
        isActive: true,
        isEligible: true,
        totalDonations: true,
        lastDonation: true,
        updatedAt: true,
      },
    });

    res.json({
      message: "Profile updated successfully",
      user: updatedUser,
    });
  } catch (error) {
    console.error("Update profile error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get User History
app.get("/api/users/history", authenticateToken, async (req, res) => {
  try {
    const history = await prisma.userHistory.findMany({
      where: { userId: req.user.id },
      orderBy: { createdAt: "desc" },
    });

    res.json({ history });
  } catch (error) {
    console.error("Get history error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get User Eligibility
app.get("/api/users/eligibility", authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: { isEligible: true, lastDonation: true },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    let daysToEligibility = 0;
    if (user.lastDonation) {
      const daysSinceLastDonation = Math.floor(
        (Date.now() - user.lastDonation.getTime()) / (1000 * 60 * 60 * 24)
      );
      daysToEligibility = Math.max(0, 120 - daysSinceLastDonation);
    }

    res.json({
      isEligible: user.isEligible,
      lastDonation: user.lastDonation,
      daysToEligibility,
    });
  } catch (error) {
    console.error("Get eligibility error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get users count
app.get("/api/users/count", async (req, res) => {
  try {
    const totalUsers = await prisma.user.count();
    res.json({ totalUsers });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get blood request statistics
app.get("/api/blood-requests/stats", async (req, res) => {
  try {
    const totalRequests = await prisma.bloodRequest.count();
    const pendingRequests = await prisma.bloodRequest.count({
      where: { status: "PENDING" },
    });
    const completedRequests = await prisma.bloodRequest.count({
      where: { status: "COMPLETED" },
    });

    res.json({
      totalRequests,
      pendingRequests,
      completedRequests,
    });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get pending requests
app.get("/api/blood-requests/pending", async (req, res) => {
  try {
    const requests = await prisma.bloodRequest.findMany({
      where: { status: "PENDING" },
      take: 10,
      orderBy: { createdAt: "desc" },
      select: {
        id: true,
        fullName: true,
        bloodType: true,
        location: true,
        urgency: true,
        createdAt: true,
      },
    });

    res.json({ requests });
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});
// ========================================
// BLOOD REQUEST ROUTES
// ========================================

// In your backend API route for /api/requests
// app.post("/api/requests", async (req, res) => {
//   try {
//     const {
//       fullName,
//       phone,
//       gender,
//       age,
//       location,
//       hospital, // Make sure this is included
//       bloodType,
//       urgency,
//       description,
//       maxDonors,
//     } = req.body;

//     // Validation
//     if (
//       !fullName ||
//       !phone ||
//       !gender ||
//       !age ||
//       !location ||
//       !bloodType ||
//       !urgency
//     ) {
//       return res.status(400).json({ error: "Required fields missing" });
//     }

//     // Create blood request with hospital
//     const bloodRequest = await prisma.bloodRequest.create({
//       data: {
//         userId: 1, // You might want to get this from auth
//         fullName,
//         phone,
//         gender,
//         age: parseInt(age),
//         location,
//         hospital, // This will be stored
//         bloodType,
//         urgency,
//         description,
//         maxDonors: maxDonors ? parseInt(maxDonors) : 5,
//       },
//     });

//     res.status(201).json({
//       message: "Blood request created successfully",
//       request: bloodRequest,
//     });
//   } catch (error) {
//     console.error("Create request error:", error);
//     res.status(500).json({ error: "Internal server error" });
//   }
// });

app.post("/api/requests", async (req, res) => {
  try {
    const {
      fullName,
      phone,
      gender,
      age,
      location,
      hospital,
      bloodType,
      urgency,
      description,
      maxDonors,
    } = req.body;

    // Validation
    if (
      !fullName ||
      !phone ||
      !gender ||
      !age ||
      !location ||
      !bloodType ||
      !urgency
    ) {
      return res.status(400).json({ error: "Required fields missing" });
    }

    // Create blood request with hospital
    const bloodRequest = await prisma.bloodRequest.create({
      data: {
        userId: 1, // You might want to get this from auth
        fullName,
        phone,
        gender,
        age: parseInt(age),
        location,
        hospital,
        bloodType,
        urgency,
        description,
        maxDonors: maxDonors ? parseInt(maxDonors) : 5,
      },
    });

    // Get all admin users to notify them
    try {
      const adminUsers = await prisma.user.findMany({
        where: {
          role: {
            in: ["ADMIN"],
          },
          isActive: true,
        },
        select: {
          id: true,
          fullName: true,
          phone: true,
          role: true,
        },
      });

      // Send notifications to all admins about the new request
      if (adminUsers.length > 0) {
        await messagingService.notifyAdminsNewRequest(adminUsers, bloodRequest);
      }

      console.log(`📨 Notified ${adminUsers.length} admins about new request`);
    } catch (notificationError) {
      console.error("Admin notification error:", notificationError);
      // Don't fail the request if notifications fail
    }

    res.status(201).json({
      message: "Blood request created successfully",
      request: bloodRequest,
    });
  } catch (error) {
    console.error("Create request error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get All Blood Requests (with filters)
app.get("/api/requests/get", async (req, res) => {
  try {
    const { status, bloodType, location, urgency } = req.query;

    const where = {};
    if (status) where.status = status;
    if (bloodType) where.bloodType = bloodType;
    if (location) where.location = location;
    if (urgency) where.urgency = urgency;

    const requests = await prisma.bloodRequest.findMany({
      where,
      include: {
        user: {
          select: {
            fullName: true,
            phone: true,
          },
        },
      },
      orderBy: { createdAt: "desc" },
    });

    res.json({ requests });
  } catch (error) {
    console.error("Get requests error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Approve blood request and notify multiple donors
app.put("/api/requests/:id/approve", async (req, res) => {
  try {
    const { id } = req.params;

    console.log(`🔄 Starting approval process for request: ${id}`);

    // Fetch blood request with all details
    const bloodRequest = await prisma.bloodRequest.findUnique({
      where: { id: parseInt(id) },
    });

    if (!bloodRequest) {
      console.log(`❌ Request not found: ${id}`);
      return res.status(404).json({ error: "Request not found" });
    }

    if (bloodRequest.status === "APPROVED") {
      console.log(`ℹ️ Request already approved: ${id}`);
      return res.status(400).json({ error: "Request is already approved" });
    }

    console.log("📋 Blood Request Details:", bloodRequest);

    // Update request status first
    const updatedRequest = await prisma.bloodRequest.update({
      where: { id: parseInt(id) },
      data: {
        status: "APPROVED",
        approvedAt: new Date(),
        adminId: 1,
      },
    });

    console.log("✅ Request status updated to APPROVED");

    // Find ALL eligible donors
    const eligibleDonors = await prisma.user.findMany({
      where: {
        bloodType: bloodRequest.bloodType,
        location: {
          contains: bloodRequest.location,
        },
        isActive: true,
        isEligible: true,
        OR: [
          { lastDonation: null },
          {
            lastDonation: {
              lt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000),
            },
          },
        ],
      },
      select: {
        id: true,
        fullName: true,
        phone: true,
        bloodType: true,
        location: true,
        lastDonation: true,
      },
      take: 50,
    });

    console.log("🎯 Eligible Donors Found:", eligibleDonors.length);

    let donorsNotified = 0;
    let notificationResults = [];
    let patientNotificationSuccess = false;

    // Send messages to ALL eligible donors
    if (eligibleDonors.length > 0) {
      console.log(
        `📤 Starting notifications for ${eligibleDonors.length} donors...`
      );

      notificationResults = await messagingService.notifyEligibleDonors(
        eligibleDonors,
        bloodRequest
      );

      donorsNotified = notificationResults.filter((r) => r.success).length;
      console.log(
        `📊 Donor notification completed: ${donorsNotified}/${eligibleDonors.length} successful`
      );
    } else {
      console.log("ℹ️ No eligible donors found for notification");
    }

    // Send confirmation to the patient
    try {
      console.log("📱 Sending approval confirmation to patient...");
      await messagingService.sendApprovalConfirmation(bloodRequest);
      patientNotificationSuccess = true;
      console.log("✅ Patient notification sent successfully");
    } catch (patientError) {
      console.error("❌ Failed to notify patient:", patientError.message);
      patientNotificationSuccess = false;
    }

    res.json({
      success: true,
      message: "Request approved successfully",
      request: updatedRequest,
      donorsNotified: donorsNotified,
      eligibleDonorsCount: eligibleDonors.length,
      patientNotified: patientNotificationSuccess,
      notificationSummary: {
        totalDonors: eligibleDonors.length,
        successful: donorsNotified,
        failed: eligibleDonors.length - donorsNotified,
      },
      notificationResults: notificationResults,
    });
  } catch (error) {
    console.error("💥 Approve request error:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
      details: error.message,
    });
  }
});

// Get approved requests with donations
app.get("/api/requests/approved", async (req, res) => {
  try {
    const requests = await prisma.bloodRequest.findMany({
      where: { status: "APPROVED" },
      include: {
        donations: {
          include: {
            donor: {
              select: { id: true, fullName: true, phone: true },
            },
          },
        },
      },
      orderBy: { createdAt: "desc" },
    });
    res.json({ requests });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// // Accept donation request
// app.post("/api/donations/accept", async (req, res) => {
//   try {
//     const { requestId, donorId, notes } = req.body;

//     const donation = await prisma.donation.create({
//       data: {
//         requestId: parseInt(requestId),
//         donorId: parseInt(donorId),
//         status: "PENDING",
//         notes,
//       },
//       include: {
//         bloodRequest: true,
//         donor: true,
//       },
//     });

//     res.json({ success: true, donation });
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// });

// Get eligible donors for a specific blood request (FIXED)
app.get("/api/requests/:id/eligible-donors", async (req, res) => {
  try {
    const { id } = req.params;

    const bloodRequest = await prisma.bloodRequest.findUnique({
      where: { id: parseInt(id) },
    });

    if (!bloodRequest) {
      return res.status(404).json({ error: "Request not found" });
    }

    const eligibleDonors = await prisma.user.findMany({
      where: {
        bloodType: bloodRequest.bloodType,
        location: {
          contains: bloodRequest.location,
        },
        isActive: true,
        isEligible: true,
        OR: [
          { lastDonation: null },
          {
            lastDonation: {
              lt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000),
            },
          },
        ],
      },
      select: {
        id: true,
        fullName: true,
        phone: true,
        bloodType: true,
        location: true,
        email: true,
        lastDonation: true,
      },
    });

    res.json({
      success: true,
      donors: eligibleDonors,
      count: eligibleDonors.length,
      bloodRequest: {
        id: bloodRequest.id,
        bloodType: bloodRequest.bloodType,
        location: bloodRequest.location,
        fullName: bloodRequest.fullName,
      },
    });
  } catch (error) {
    console.error("Get eligible donors error:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
    });
  }
});

// Check user eligibility to donate
app.get("/api/users/eligibility", async (req, res) => {
  try {
    const token = req.headers.authorization?.replace("Bearer ", "");

    if (!token) {
      return res.status(401).json({ error: "Authentication required" });
    }

    // Verify token and get user ID (you'll need to implement JWT verification)
    const decoded = jwt.verify(token, process.env.JWT_SECRET); // Make sure you have JWT setup
    const userId = decoded.userId;

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        isEligible: true,
        lastDonation: true,
        totalDonations: true,
      },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Check eligibility based on last donation date
    let isEligible = true;
    let daysToEligibility = 0;
    let lastDonationDate = null;

    if (user.lastDonation) {
      const lastDonation = new Date(user.lastDonation);
      const today = new Date();
      const daysSinceLastDonation = Math.floor(
        (today - lastDonation) / (1000 * 60 * 60 * 24)
      );

      // Users can donate every 90 days (3 months)
      const requiredWaitDays = 90;

      if (daysSinceLastDonation < requiredWaitDays) {
        isEligible = false;
        daysToEligibility = requiredWaitDays - daysSinceLastDonation;
      }

      lastDonationDate = user.lastDonation;
    }

    // Also check if user is marked as eligible in database
    if (!user.isEligible) {
      isEligible = false;
    }

    res.json({
      isEligible,
      daysToEligibility,
      lastDonation: lastDonationDate,
      totalDonations: user.totalDonations || 0,
      message: isEligible
        ? "You are eligible to donate blood"
        : `You need to wait ${daysToEligibility} more days before donating again`,
    });
  } catch (error) {
    console.error("Eligibility check error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// // Get eligible donors for a specific blood request
// app.get("/api/requests/:id/eligible-donors", async (req, res) => {
//   try {
//     const { id } = req.params;

//     const bloodRequest = await prisma.bloodRequest.findUnique({
//       where: { id: parseInt(id) },
//     });

//     if (!bloodRequest) {
//       return res.status(404).json({ error: "Request not found" });
//     }

//     const eligibleDonors = await prisma.user.findMany({
//       where: {
//         bloodType: bloodRequest.bloodType,
//         location: bloodRequest.location,
//         isActive: true,
//         isEligible: true,
//         OR: [
//           { lastDonation: null },
//           {
//             lastDonation: {
//               lt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000),
//             },
//           },
//         ],
//       },
//       select: {
//         id: true,
//         fullName: true,
//         phone: true,
//         bloodType: true,
//         location: true,
//         email: true,
//         lastDonation: true,
//       },
//     });

//     res.json({
//       success: true,
//       donors: eligibleDonors,
//       count: eligibleDonors.length,
//       bloodRequest: {
//         id: bloodRequest.id,
//         bloodType: bloodRequest.bloodType,
//         location: bloodRequest.location,
//         fullName: bloodRequest.fullName,
//       },
//     });
//   } catch (error) {
//     console.error("Get eligible donors error:", error);
//     res.status(500).json({
//       success: false,
//       error: "Internal server error",
//     });
//   }
// });

// Add this specific route for user's own requests
app.get("/api/requests/my-requests", async (req, res) => {
  try {
    // Get token from Authorization header
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        error: "Token ma ahan mid jira",
      });
    }

    // Verify and decode the token
    let decodedToken;
    try {
      decodedToken = jwt.verify(
        token,
        process.env.JWT_SECRET || "fallback-secret"
      );
      console.log("Token verified successfully. User ID:", decodedToken.userId);
    } catch (jwtError) {
      console.error("Token verification failed:", jwtError);
      return res.status(401).json({
        success: false,
        error: "Token waa khalad ama waa dhacay",
      });
    }

    const userId = decodedToken.userId;

    if (!userId) {
      return res.status(401).json({
        success: false,
        error: "User ID ma jiro token-ka",
      });
    }

    console.log("📋 Fetching requests for user ID:", userId);

    const requests = await prisma.bloodRequest.findMany({
      where: {
        userId: parseInt(userId),
      },
      include: {
        donations: {
          include: {
            donor: {
              select: {
                id: true,
                fullName: true,
                phone: true,
                bloodType: true,
                location: true,
              },
            },
          },
        },
      },
      orderBy: { createdAt: "desc" },
    });

    console.log(`✅ Found ${requests.length} requests for user ${userId}`);

    res.json({
      success: true,
      requests: requests || [],
    });
  } catch (error) {
    console.error("💥 Get user requests error:", error);
    res.status(500).json({
      success: false,
      error: "Qalad ka dhacay server-ka gudahiisa",
    });
  }
});

// Get Blood Request by ID
app.get("/api/requests/:id", async (req, res) => {
  try {
    const { id } = req.params;

    // Convert string ID to integer
    const requestId = parseInt(id);
    if (isNaN(requestId)) {
      return res.status(400).json({ error: "Invalid request ID" });
    }

    const request = await prisma.bloodRequest.findUnique({
      where: { id: requestId }, // Use the converted integer
      include: {
        user: {
          select: {
            fullName: true,
            phone: true,
          },
        },
        donations: {
          include: {
            donor: {
              select: {
                fullName: true,
                phone: true,
                bloodType: true,
              },
            },
          },
        },
      },
    });

    if (!request) {
      return res.status(404).json({ error: "Request not found" });
    }

    res.json({ request });
  } catch (error) {
    console.error("Get request by ID error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Delete Blood Request
app.delete("/api/requests/:id", async (req, res) => {
  try {
    const { id } = req.params;

    // Convert string ID to integer
    const requestId = parseInt(id);
    if (isNaN(requestId)) {
      return res.status(400).json({ error: "Invalid request ID" });
    }

    // Check if user owns the request
    const request = await prisma.bloodRequest.findUnique({
      where: { id: requestId }, // Use the converted integer
      select: { userId: true, status: true },
    });

    if (!request) {
      return res.status(404).json({ error: "Request not found" });
    }

    if (request.userId !== req.user.id) {
      return res
        .status(403)
        .json({ error: "Not authorized to delete this request" });
    }

    if (request.status !== "PENDING") {
      return res
        .status(400)
        .json({ error: "Can only delete pending requests" });
    }

    await prisma.bloodRequest.delete({
      where: { id: requestId }, // Use the converted integer
    });

    res.json({ message: "Request deleted successfully" });
  } catch (error) {
    console.error("Delete request error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Delete user account
// Soft delete user account (recommended)
app.put("/api/users/deactivate-account", async (req, res) => {
  try {
    const token = req.headers.authorization?.replace("Bearer ", "");

    if (!token) {
      return res.status(401).json({ error: "Authentication required" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.userId;

    console.log(`🔒 Deactivating account for user: ${userId}`);

    const user = await prisma.user.findUnique({
      where: { id: parseInt(userId) },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Soft delete by deactivating the account
    const deactivatedUser = await prisma.user.update({
      where: { id: parseInt(userId) },
      data: {
        isActive: false,
        isEligible: false,
        deactivatedAt: new Date(),
        phone: `deactivated_${user.phone}_${Date.now()}`, // Make phone unique
        email: user.email ? `deactivated_${user.email}_${Date.now()}` : null,
      },
    });

    console.log(`✅ Account deactivated for user: ${userId}`);

    res.json({
      success: true,
      message: "Account deactivated successfully",
      deactivatedAt: deactivatedUser.deactivatedAt,
    });
  } catch (error) {
    console.error("Deactivate account error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to deactivate account",
    });
  }
});

// GET THE ELLIGABLE USERS
app.get("/eligible-donors", async (req, res) => {
  try {
    const { bloodType, location, hospital } = req.query;

    if (!bloodType || !location) {
      return res
        .status(400)
        .json({ error: "Blood type and location are required" });
    }

    const eligibleDonors = await prisma.user.findMany({
      where: {
        bloodType: bloodType,
        location: location,
        isActive: true,
        isEligible: true,
        // Exclude users who donated recently (within 3 months)
        OR: [
          { lastDonation: null },
          {
            lastDonation: {
              lt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000),
            },
          },
        ],
      },
      select: {
        id: true,
        fullName: true,
        phone: true,
        bloodType: true,
        location: true,
        lastDonation: true,
        totalDonations: true,
      },
    });

    res.json({
      success: true,
      count: eligibleDonors.length,
      users: eligibleDonors,
    });
  } catch (error) {
    console.error("Get eligible donors error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get accepted donations for a blood request
app.get("/api/donations/accepted", async (req, res) => {
  try {
    const { requestId } = req.query;

    let whereClause = {
      status: {
        in: ["ACCEPTED", "PENDING"],
      },
    };

    if (requestId) {
      whereClause.requestId = parseInt(requestId);
    }

    const donations = await prisma.donation.findMany({
      where: whereClause,
      include: {
        donor: {
          select: {
            id: true,
            fullName: true,
            phone: true,
            bloodType: true,
            location: true,
            lastDonation: true,
          },
        },
        bloodRequest: {
          select: {
            id: true,
            bloodType: true,
            location: true,
            hospital: true,
            fullName: true,
          },
        },
      },
      orderBy: { createdAt: "desc" },
    });

    console.log(`✅ Found ${donations.length} donations`);

    res.json({
      success: true,
      donations,
      bloodRequest: donations[0]?.bloodRequest || null,
    });
  } catch (error) {
    console.error("💥 Get accepted donations error:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
      details: error.message,
    });
  }
});

// Approve blood request and notify donors
app.put("/:id/status", async (req, res) => {
  try {
    const { id } = req.params;
    const { status, rejectReason } = req.body;

    const bloodRequest = await prisma.bloodRequest.findUnique({
      where: { id: parseInt(id) },
    });

    if (!bloodRequest) {
      return res.status(404).json({ error: "Request not found" });
    }

    // Update request status
    const updatedRequest = await prisma.bloodRequest.update({
      where: { id: parseInt(id) },
      data: {
        status: status,
        approved: status === "APPROVED",
        approvedBy: status === "APPROVED" ? req.user.userId.toString() : null,
        approvedAt: status === "APPROVED" ? new Date() : null,
        rejectReason: status === "REJECTED" ? rejectReason : null,
      },
    });

    // If approved, find eligible donors and send notifications
    if (status === "APPROVED") {
      try {
        const eligibleDonors = await prisma.user.findMany({
          where: {
            bloodType: bloodRequest.bloodType,
            location: bloodRequest.location,
            isActive: true,
            isEligible: true,
            OR: [
              { lastDonation: null },
              {
                lastDonation: {
                  lt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000),
                },
              },
            ],
          },
          select: {
            id: true,
            fullName: true,
            phone: true,
            bloodType: true,
            location: true,
          },
        });

        // Send WhatsApp messages to eligible donors
        if (eligibleDonors.length > 0) {
          await messagingService.notifyEligibleDonors(
            eligibleDonors,
            bloodRequest
          );
        }

        // Send confirmation to the patient
        await messagingService.sendApprovalConfirmation(bloodRequest);

        res.json({
          message: "Request approved successfully",
          request: updatedRequest,
          donorsNotified: eligibleDonors.length,
          donors: eligibleDonors,
        });
      } catch (notificationError) {
        console.error("Notification error:", notificationError);
        // Still return success even if notifications fail
        res.json({
          message: "Request approved but notifications failed",
          request: updatedRequest,
          notificationError: notificationError.message,
        });
      }
    } else {
      res.json({
        message: `Request ${status.toLowerCase()} successfully`,
        request: updatedRequest,
      });
    }
  } catch (error) {
    console.error("Update request status error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get donations for a specific blood request
app.get("/api/requests/:id/donations", async (req, res) => {
  try {
    const { id } = req.params;

    const donations = await prisma.donation.findMany({
      where: { requestId: parseInt(id) },
      include: {
        donor: {
          select: {
            id: true,
            fullName: true,
            phone: true,
            bloodType: true,
            location: true,
          },
        },
      },
      orderBy: { createdAt: "desc" },
    });

    res.json({
      success: true,
      donations: donations,
      count: donations.length,
    });
  } catch (error) {
    console.error("Get donations error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/register/hospital", async (req, res) => {
  try {
    const { hospital_name, phone, location } = req.body;

    // Validation
    if (!hospital_name || !phone || !location) {
      return res
        .status(400)
        .json({ error: "Goobaha loo baahan yahay waa laga maarmay" });
    }

    // Create admin
    const hospital = await prisma.hospital.create({
      data: {
        hospital_name,
        phone,
        location,
      },
    });

    res.status(201).json({
      message: "Cusbitaalka si sax ah ayaa loo diiwaangaliyay",
      hospital,
    });
  } catch (error) {
    console.error("Cusbitaalka Lama registration error:", error);
    res.status(500).json({ error: "Khalad server dhexdii saaran" });
  }
});

app.get("/api/hospitals", async (req, res) => {
  try {
    const hospitals = await prisma.hospital.findMany({
      orderBy: { createdAt: "desc" },
    });

    res.json({ hospitals });
  } catch (error) {
    console.error("Get Hospitals error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Update hospital status
app.put("/api/hospitals/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { isActive } = req.body;

    const hospital = await prisma.hospital.update({
      where: { id: parseInt(id) },
      data: { isActive },
    });

    res.json({
      message: "Xaaladda cusbitaalka si guul leh ayaa loo cusboonaysiiyay",
      hospital,
    });
  } catch (error) {
    console.error("Update hospital error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Delete hospital
app.delete("/api/hospitals/:id", async (req, res) => {
  try {
    const { id } = req.params;

    await prisma.hospital.delete({
      where: { id: parseInt(id) },
    });

    res.json({ message: "Cusbitaalka si guul leh ayaa loo tirtiray" });
  } catch (error) {
    console.error("Delete hospital error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Add this to your backend routes
// Get user donations history
app.get("/api/users/:userId/donations", async (req, res) => {
  try {
    const { userId } = req.params;

    // Alternative: Get user ID from token in header instead of req.user
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
      return res.status(401).json({ error: "Token ma ahan mid jira" });
    }

    let decodedToken;
    try {
      decodedToken = jwt.verify(
        token,
        process.env.JWT_SECRET || "fallback-secret"
      );
    } catch (jwtError) {
      return res.status(401).json({ error: "Token waa khalad ama waa dhacay" });
    }

    // Verify the authenticated user is accessing their own data
    if (parseInt(userId) !== decodedToken.userId) {
      return res.status(403).json({
        error: "Ma haysatid ogolaansho aan galitaan dhammaan xogtaan",
      });
    }

    const donations = await prisma.donation.findMany({
      where: {
        donorId: parseInt(userId),
      },
      include: {
        bloodRequest: {
          select: {
            fullName: true,
            bloodType: true,
            hospital: true,
          },
        },
      },
      orderBy: {
        createdAt: "desc",
      },
      take: 10, // Get last 10 donations
    });

    // Format the response
    const formattedDonations = donations.map((donation) => ({
      id: donation.id,
      status: donation.status,
      bloodType: donation.bloodRequest.bloodType,
      hospital: donation.bloodRequest.hospital,
      recipientName: donation.bloodRequest.fullName,
      donationDate: donation.completedAt || donation.createdAt,
      notes: donation.notes,
      createdAt: donation.createdAt,
    }));

    res.json({
      donations: formattedDonations,
      total: formattedDonations.length,
    });
  } catch (error) {
    console.error("Error fetching user donations:", error);
    res.status(500).json({ error: "Qalad ka dhacay server-ka gudahiisa" });
  }
});

app.get("/api/users/:userId/last-donation", async (req, res) => {
  try {
    const { userId } = req.params;

    // Alternative: Get user ID from token in header instead of req.user
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
      return res.status(401).json({ error: "Token ma ahan mid jira" });
    }

    let decodedToken;
    try {
      decodedToken = jwt.verify(
        token,
        process.env.JWT_SECRET || "fallback-secret"
      );
    } catch (jwtError) {
      return res.status(401).json({ error: "Token waa khalad ama waa dhacay" });
    }

    // Verify the authenticated user is accessing their own data
    if (parseInt(userId) !== decodedToken.userId) {
      return res.status(403).json({
        error: "Ma haysatid ogolaansho aan galitaan dhammaan xogtaan",
      });
    }

    // Find the most recent completed donation
    const lastDonation = await prisma.donation.findFirst({
      where: {
        donorId: parseInt(userId),
        status: "COMPLETED",
      },
      orderBy: {
        completedAt: "desc",
      },
      select: {
        completedAt: true,
      },
    });

    res.json({
      lastDonation: lastDonation?.completedAt || null,
    });
  } catch (error) {
    console.error("Error fetching last donation:", error);
    res.status(500).json({ error: "Qalad ka dhacay server-ka gudahiisa" });
  }
});

// Get requests by status
app.get("/get", async (req, res) => {
  try {
    const { status } = req.query;

    const requests = await prisma.bloodRequest.findMany({
      where: status ? { status: status } : {},
      include: {
        user: {
          select: {
            fullName: true,
            phone: true,
          },
        },
      },
      orderBy: {
        createdAt: "desc",
      },
    });

    res.json({ requests });
  } catch (error) {
    console.error("Get requests error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ========================================
// DONATION ROUTES
// ========================================

// Create Donation
// Create Donation (Enhanced)
app.post("/api/donations", async (req, res) => {
  try {
    const { requestId, donorId, notes } = req.body;

    if (!requestId || !donorId) {
      return res
        .status(400)
        .json({ error: "Request ID and donor ID are required" });
    }

    // Check if user is eligible
    const donor = await prisma.user.findUnique({
      where: { id: parseInt(donorId) },
      select: {
        isEligible: true,
        lastDonation: true,
        fullName: true,
        phone: true,
        bloodType: true,
        location: true,
      },
    });

    if (!donor || !donor.isEligible) {
      return res.status(400).json({
        error:
          "You are not eligible to donate at this time. Please check your eligibility status.",
      });
    }

    // Check if request exists and is approved
    const request = await prisma.bloodRequest.findUnique({
      where: { id: parseInt(requestId) },
      include: {
        user: {
          select: {
            fullName: true,
            phone: true,
          },
        },
      },
    });

    if (!request) {
      return res.status(404).json({ error: "Blood request not found" });
    }

    if (request.status !== "APPROVED") {
      return res
        .status(400)
        .json({ error: "Can only donate to approved requests" });
    }

    // Check if user already donated to this request
    const existingDonation = await prisma.donation.findFirst({
      where: {
        requestId: parseInt(requestId),
        donorId: parseInt(donorId),
      },
    });

    if (existingDonation) {
      return res
        .status(400)
        .json({ error: "You have already responded to this request" });
    }

    // Create donation
    const donation = await prisma.donation.create({
      data: {
        requestId: parseInt(requestId),
        donorId: parseInt(donorId),
        notes: notes || "Available to donate blood",
        status: "PENDING",
      },
    });

    // Send WhatsApp notification to requester
    try {
      const message = `🎉 *DHEEFSADE CUSUB AYAAD KA HELAY!* 🎉

  *Macluumaadka Qofka Dhiiga Codsaday:*
  *Magaca:* ${donor.fullName}
  *Lambarka:* ${donor.phone}
  *Nooca Dhiigga:* ${donor.bloodType
    .replace("_", "+")
    .replace("POSITIVE", "+")
    .replace("NEGATIVE", "-")}
  *Goobta:* ${donor.location}

  *Fadlan la xiriir samafalaha si aad u hesho ballanta dhiigga.*

  *Mahadsanid!*
  - Badbaado Blood Donation App`;

      await messagingService.sendWhatsAppMessage(request.user.phone, message);
    } catch (whatsappError) {
      console.error("WhatsApp notification failed:", whatsappError);
    }

    res.status(201).json({
      message: "Donation response created successfully",
      donation: donation,
    });
  } catch (error) {
    console.error("Create donation error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get Donations
app.get("/api/donations", async (req, res) => {
  try {
    const { status } = req.query;

    const where = { donorId: req.user.id };
    if (status) where.status = status;

    const donations = await prisma.donation.findMany({
      where,
      include: {
        bloodRequest: {
          select: {
            fullName: true,
            bloodType: true,
            location: true,
            urgency: true,
          },
        },
      },
      orderBy: { createdAt: "desc" },
    });

    res.json({ donations });
  } catch (error) {
    console.error("Get donations error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Create donation and send WhatsApp notification
app.post("/api/donations/accept", async (req, res) => {
  try {
    const { requestId, donorId, notes } = req.body;

    if (!requestId || !donorId) {
      return res
        .status(400)
        .json({ error: "Request ID and donor ID are required" });
    }

    // Get request details
    const bloodRequest = await prisma.bloodRequest.findUnique({
      where: { id: parseInt(requestId) },
      include: {
        user: {
          select: {
            fullName: true,
            phone: true,
            location: true,
          },
        },
      },
    });

    if (!bloodRequest) {
      return res.status(404).json({ error: "Blood request not found" });
    }

    // Get donor details
    const donor = await prisma.user.findUnique({
      where: { id: parseInt(donorId) },
      select: {
        id: true,
        fullName: true,
        phone: true,
        bloodType: true,
        location: true,
      },
    });

    if (!donor) {
      return res.status(404).json({ error: "Donor not found" });
    }

    // Check if donor already accepted this request
    const existingDonation = await prisma.donation.findFirst({
      where: {
        requestId: parseInt(requestId),
        donorId: parseInt(donorId),
      },
    });

    if (existingDonation) {
      return res
        .status(400)
        .json({ error: "You have already accepted this request" });
    }

    // Create donation
    const donation = await prisma.donation.create({
      data: {
        requestId: parseInt(requestId),
        donorId: parseInt(donorId),
        notes: notes || "Available to donate blood",
        status: "PENDING",
      },
      include: {
        donor: {
          select: {
            fullName: true,
            phone: true,
            bloodType: true,
          },
        },
        bloodRequest: {
          select: {
            fullName: true,
            phone: true,
            bloodType: true,
            location: true,
          },
        },
      },
    });

    // Send WhatsApp notification to requester
    try {
      const message = `*SAMAFALE DHIIGGA SHUBAYA AYAA KU AQBALAY!* 

      *Macluumaadka Dhiig Shubaha:*
      *Magaca:* ${donor.fullName}
      *Taleefanka:* ${donor.phone}
      *Nooca Dhiigga:* ${donor.bloodType
        .replace("_", "+")
        .replace("POSITIVE", "+")
        .replace("NEGATIVE", "-")}
      *Goobta:* ${donor.location}

      *Macluumaadka Codsigaaga:*
      *Nooca Dhiigga:* ${bloodRequest.bloodType
        .replace("_", "+")
        .replace("POSITIVE", "+")
        .replace("NEGATIVE", "-")}
      *Goobta:* ${bloodRequest.location}

    *Fadlan la xiriir dheefsadaha si aad u hesho ballanta dhiigga.*

    *Mahadsanid!*
    - Badbaado Blood Donation App`;

      await messagingService.sendWhatsAppMessage(
        bloodRequest.user.phone,
        message
      );
    } catch (whatsappError) {
      console.error("WhatsApp notification failed:", whatsappError);
      // Continue even if WhatsApp fails
    }

    // Check if request has reached maximum donors
    const donationCount = await prisma.donation.count({
      where: { requestId: parseInt(requestId) },
    });

    if (donationCount >= bloodRequest.maxDonors) {
      await prisma.bloodRequest.update({
        where: { id: parseInt(requestId) },
        data: { status: "COMPLETED" },
      });
    }

    res.status(201).json({
      success: true,
      message: "Request accepted successfully",
      donation: donation,
      donorsCount: donationCount,
      requestCompleted: donationCount >= bloodRequest.maxDonors,
    });
  } catch (error) {
    console.error("Accept donation error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});
// Update Donation Status
app.put("/api/donations/:id/status", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!status) {
      return res.status(400).json({ error: "Status is required" });
    }

    // Check if donation belongs to user
    const donation = await prisma.donation.findUnique({
      where: { id },
      select: { donorId: true },
    });

    if (!donation) {
      return res.status(404).json({ error: "Donation not found" });
    }

    if (donation.donorId !== req.user.id) {
      return res
        .status(403)
        .json({ error: "Not authorized to update this donation" });
    }

    const updateData = { status };
    if (status === "ACCEPTED") {
      updateData.acceptedAt = new Date();
    } else if (status === "COMPLETED") {
      updateData.completedAt = new Date();

      // Update user eligibility and donation count
      await prisma.user.update({
        where: { id: req.user.id },
        data: {
          isEligible: false,
          lastDonation: new Date(),
          totalDonations: {
            increment: 1,
          },
        },
      });
    }

    const updatedDonation = await prisma.donation.update({
      where: { id },
      data: updateData,
    });

    res.json({
      message: "Donation status updated successfully",
      donation: updatedDonation,
    });
  } catch (error) {
    console.error("Update donation status error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get user's active blood requests
app.get("/api/requests/user/:userId/active", async (req, res) => {
  try {
    const { userId } = req.params;

    const requests = await prisma.bloodRequest.findMany({
      where: {
        userId: parseInt(userId),
        status: { in: ["APPROVED", "PENDING"] }, // Active statuses
      },
      orderBy: { createdAt: "desc" },
      take: 1, // Get only the most recent active request
    });

    res.json({ requests });
  } catch (error) {
    console.error("Get user active requests error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Mark blood request as completed
app.put("/api/requests/:id/status", async (req, res) => {
  try {
    const { id } = req.params;
    const { status, rejectReason } = req.body;

    console.log(`🔄 Updating request ${id} status to:`, status);

    // Check if request exists
    const bloodRequest = await prisma.bloodRequest.findUnique({
      where: { id: parseInt(id) },
    });

    if (!bloodRequest) {
      console.log(`❌ Request not found: ${id}`);
      return res.status(404).json({ error: "Blood request not found" });
    }

    // Validate status
    const validStatuses = [
      "PENDING",
      "APPROVED",
      "REJECTED",
      "COMPLETED",
      "CANCELLED",
    ];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        error: "Invalid status",
        validStatuses,
      });
    }

    // Prepare update data
    const updateData = {
      status: status,
      updatedAt: new Date(),
    };

    // Add timestamp based on status
    if (status === "COMPLETED") {
      updateData.completedAt = new Date();
    } else if (status === "REJECTED") {
      updateData.rejectedAt = new Date();
      if (rejectReason) {
        updateData.rejectReason = rejectReason;
      }
    } else if (status === "APPROVED") {
      updateData.approvedAt = new Date();
    }

    // Update the request
    const updatedRequest = await prisma.bloodRequest.update({
      where: { id: parseInt(id) },
      data: updateData,
      include: {
        donations: {
          include: {
            donor: {
              select: {
                id: true,
                fullName: true,
                phone: true,
              },
            },
          },
        },
        user: {
          select: {
            id: true,
            fullName: true,
            phone: true,
          },
        },
      },
    });

    console.log(`✅ Request ${id} status updated to: ${status}`);

    // If marking as COMPLETED, also update related donations
    if (status === "COMPLETED") {
      try {
        // Mark all accepted donations for this request as completed
        await prisma.donation.updateMany({
          where: {
            requestId: parseInt(id),
            status: "ACCEPTED",
          },
          data: {
            status: "COMPLETED",
            completedAt: new Date(),
            updatedAt: new Date(),
          },
        });

        console.log(`✅ Updated donations for request ${id} to COMPLETED`);
      } catch (donationError) {
        console.error("❌ Error updating donations:", donationError);
        // Don't fail the whole request if donation update fails
      }
    }

    res.json({
      success: true,
      message: `Request ${status.toLowerCase()} successfully`,
      request: updatedRequest,
    });
  } catch (error) {
    console.error("💥 Update request status error:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
      details: error.message,
    });
  }
});

// Confirm a donor
// Confirm a donor (mark donation as completed)
app.put("/api/donations/:id/confirm", async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    const donation = await prisma.donation.update({
      where: { id: parseInt(id) },
      data: {
        status: "COMPLETED", // Use "COMPLETED" instead of "CONFIRMED"
        completedAt: new Date(),
      },
      include: {
        donor: true,
        bloodRequest: true,
      },
    });

    // Send completion notification to donor
    // You can implement WhatsApp notification here

    res.json({
      success: true,
      message: "Donation marked as completed",
      donation,
    });
  } catch (error) {
    console.error("Confirm donor error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});
// ========================================
// ADMIN ROUTES
// ========================================

// Get Admin Dashboard Stats
app.get("/api/admin/dashboard", async (req, res) => {
  try {
    const [totalUsers, totalRequests, pendingRequests, completedDonations] =
      await Promise.all([
        prisma.user.count({ where: { isActive: true } }),
        prisma.bloodRequest.count(),
        prisma.bloodRequest.count({ where: { status: "PENDING" } }),
        prisma.donation.count({ where: { status: "COMPLETED" } }),
      ]);

    res.json({
      stats: {
        totalUsers,
        totalRequests,
        pendingRequests,
        completedDonations,
      },
    });
  } catch (error) {
    console.error("Get dashboard stats error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// authenticateAdmin

// Get All Users (Admin)
app.get("/api/admin/users", async (req, res) => {
  try {
    const { search, status, bloodType, location } = req.query;

    const where = {};
    if (search) {
      where.OR = [
        { fullName: { contains: search, mode: "insensitive" } },
        { email: { contains: search, mode: "insensitive" } },
        { location: { contains: search, mode: "insensitive" } },
      ];
    }
    if (status) where.isActive = status === "active";
    if (bloodType) where.bloodType = bloodType;
    if (location) where.location = location;

    const users = await prisma.user.findMany({
      where,
      select: {
        id: true,
        fullName: true,
        phone: true,
        bloodType: true,
        location: true,
        isActive: true,
        isEligible: true,
        totalDonations: true,
        lastDonation: true,
        createdAt: true,
      },
      orderBy: { createdAt: "desc" },
    });

    res.json({ users });
  } catch (error) {
    console.error("Get users error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get All Users (for admin panel)
app.get("/api/users", async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        fullName: true,
        email: true,
        phone: true,
        role: true,
        isActive: true,
        isEligible: true,
        totalDonations: true,
        lastDonation: true,
        createdAt: true,
        updatedAt: true,
        _count: {
          select: {
            bloodRequest: true,
          },
        },
      },
      orderBy: { createdAt: "desc" },
    });

    res.json(users);
  } catch (error) {
    console.error("Get users error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Delete User
app.delete("/api/users/:id", async (req, res) => {
  try {
    const userId = parseInt(req.params.id);

    if (isNaN(userId) || userId <= 0) {
      return res.status(400).json({ 
        success: false,
        error: "Invalid user ID" 
      });
    }

    console.log(`🗑️  Attempting to delete user ID: ${userId}`);

    // Check if user exists
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        _count: {
          select: {
            businesses: true,
            products: true,
            professionals: true,
            bloodRequest: true,
          },
        },
      },
    });

    if (!user) {
      console.log(`❌ User not found: ${userId}`);
      return res.status(404).json({ 
        success: false,
        error: "User not found" 
      });
    }

    // Prevent deletion of admin users (safety check)
    if (user.role === "ADMIN") {
      console.log(`❌ Cannot delete admin user: ${userId}`);
      return res.status(403).json({ 
        success: false,
        error: "Cannot delete admin users" 
      });
    }

    console.log(`📋 User found: ${user.name} (${user.email})`);
    console.log(`📊 Related data counts:`, user._count);

    // Delete user and all related data using transaction
    await prisma.$transaction(async (tx) => {
      // Delete user's sessions if they exist
      try {
        const deletedSessions = await tx.session.deleteMany({
          where: { userId: userId },
        });
        console.log(`✅ Deleted ${deletedSessions.count} session(s)`);
      } catch (e) {
        console.log(`ℹ️  Sessions table not found or already deleted: ${e.message}`);
      }

      // Delete user's plan upgrade requests
      try {
        const deletedUpgrades = await tx.planUpgradeRequest.deleteMany({
          where: { userId: userId },
        });
        console.log(`✅ Deleted ${deletedUpgrades.count} plan upgrade request(s)`);
      } catch (e) {
        console.log(`ℹ️  Plan upgrade requests not found or already deleted: ${e.message}`);
      }

      // Delete user's professionals
      try {
        const deletedProfessionals = await tx.professional.deleteMany({
          where: { userId: userId },
        });
        console.log(`✅ Deleted ${deletedProfessionals.count} professional(s)`);
      } catch (e) {
        console.log(`ℹ️  Professionals not found or already deleted: ${e.message}`);
      }

      // Delete user's products
      try {
        const deletedProducts = await tx.product.deleteMany({
          where: { userId: userId },
        });
        console.log(`✅ Deleted ${deletedProducts.count} product(s)`);
      } catch (e) {
        console.log(`ℹ️  Products not found or already deleted: ${e.message}`);
      }

      // Delete user's businesses
      try {
        const deletedBusinesses = await tx.business.deleteMany({
          where: { ownerId: userId },
        });
        console.log(`✅ Deleted ${deletedBusinesses.count} business(es)`);
      } catch (e) {
        console.log(`ℹ️  Businesses not found or already deleted: ${e.message}`);
      }

      // Delete user's blood requests
      try {
        const deletedRequests = await tx.bloodRequest.deleteMany({
          where: { userId: userId },
        });
        console.log(`✅ Deleted ${deletedRequests.count} blood request(s)`);
      } catch (e) {
        console.log(`ℹ️  Blood requests not found or already deleted: ${e.message}`);
      }

      // Delete user's donations
      try {
        const deletedDonations = await tx.donation.deleteMany({
          where: { donorId: userId },
        });
        console.log(`✅ Deleted ${deletedDonations.count} donation(s)`);
      } catch (e) {
        console.log(`ℹ️  Donations not found or already deleted: ${e.message}`);
      }

      // Delete user's notifications
      try {
        const deletedNotifications = await tx.userNotification.deleteMany({
          where: { userId: userId },
        });
        console.log(`✅ Deleted ${deletedNotifications.count} notification(s)`);
      } catch (e) {
        console.log(`ℹ️  Notifications not found or already deleted: ${e.message}`);
      }

      // Delete user's history if exists
      try {
        const deletedHistory = await tx.userHistory.deleteMany({
          where: { userId: userId },
        });
        console.log(`✅ Deleted ${deletedHistory.count} history record(s)`);
      } catch (e) {
        console.log(`ℹ️  User history not found or already deleted: ${e.message}`);
      }

      // Finally delete the user
      await tx.user.delete({
        where: { id: userId },
      });
      console.log(`✅ User deleted successfully`);
    });

    console.log(`✅ User deletion completed for ID: ${userId}`);

    res.json({
      success: true,
      message: "User and all related data deleted successfully",
      deletedUser: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("❌ Error deleting user:", error);
    console.error("❌ Error code:", error.code);
    console.error("❌ Error message:", error.message);
    console.error("❌ Error stack:", error.stack);

    // Handle Prisma specific errors
    if (error.code === "P2025") {
      return res.status(404).json({ 
        success: false,
        error: "User not found" 
      });
    }

    // Handle foreign key constraint errors
    if (error.code === "P2003") {
      return res.status(400).json({
        success: false,
        error: "Cannot delete user due to existing relationships",
        details: "Please remove all related data first",
      });
    }

    // Handle transaction errors
    if (error.code === "P2034") {
      return res.status(500).json({
        success: false,
        error: "Transaction failed",
        details: error.message,
      });
    }

    res.status(500).json({ 
      success: false,
      error: "Failed to delete user",
      details: error.message,
      code: error.code || "UNKNOWN_ERROR"
    });
  }
});

// Update User Status (Admin)
app.put("/api/admin/users/:id/status", async (req, res) => {
  try {
    const { id } = req.params;
    const { isActive } = req.body;

    if (typeof isActive !== "boolean") {
      return res.status(400).json({ error: "isActive must be a boolean" });
    }

    const updatedUser = await prisma.user.update({
      where: { id },
      data: { isActive },
      select: {
        id: true,
        fullName: true,
        isActive: true,
        updatedAt: true,
      },
    });

    res.json({
      message: `User ${isActive ? "activated" : "deactivated"} successfully`,
      user: updatedUser,
    });
  } catch (error) {
    console.error("Update user status error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get All Blood Requests (Admin)
app.get("/api/admin/requests", async (req, res) => {
  try {
    const { status, bloodType, location, urgency } = req.query;

    const where = {};
    if (status) where.status = status;
    if (bloodType) where.bloodType = bloodType;
    if (location) where.location = location;
    if (urgency) where.urgency = urgency;

    const requests = await prisma.bloodRequest.findMany({
      where,
      include: {
        user: {
          select: {
            fullName: true,
            phone: true,
          },
        },
        donations: {
          include: {
            donor: {
              select: {
                fullName: true,
                phone: true,
                bloodType: true,
              },
            },
          },
        },
      },
      orderBy: { createdAt: "desc" },
    });

    res.json({ requests });
  } catch (error) {
    console.error("Get admin requests error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Approve Blood Request (Admin)
app.put(
  "/api/admin/requests/:id/approve",

  async (req, res) => {
    try {
      const { id } = req.params;

      const updatedRequest = await prisma.bloodRequest.update({
        where: { id },
        data: {
          status: "APPROVED",
          approvedAt: new Date(),
          adminId: req.admin.id,
        },
      });

      res.json({
        message: "Request approved successfully",
        request: updatedRequest,
      });
    } catch (error) {
      console.error("Approve request error:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

// Reject Blood Request (Admin)
app.put(
  "/api/admin/requests/:id/reject",

  async (req, res) => {
    try {
      const { id } = req.params;
      const { rejectReason } = req.body;

      if (!rejectReason) {
        return res.status(400).json({ error: "Rejection reason is required" });
      }

      const updatedRequest = await prisma.bloodRequest.update({
        where: { id },
        data: {
          status: "REJECTED",
          rejectedAt: new Date(),
          adminId: req.admin.id,
          rejectReason,
        },
      });

      res.json({
        message: "Request rejected successfully",
        request: updatedRequest,
      });
    } catch (error) {
      console.error("Reject request error:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

// ========================================
// NOTIFICATION ROUTES
// ========================================

// Send Admin Notification
app.post("/api/admin/notifications", authenticateAdmin, async (req, res) => {
  try {
    const { title, message, targetType, targetValue, priority } = req.body;

    if (!title || !message || !targetType) {
      return res
        .status(400)
        .json({ error: "Title, message, and target type are required" });
    }

    const notification = await prisma.adminNotification.create({
      data: {
        adminId: req.admin.id,
        title,
        message,
        targetType,
        targetValue,
        priority: priority || "NORMAL",
        status: "SENT",
        sentAt: new Date(),
      },
    });

    res.status(201).json({
      message: "Notification sent successfully",
      notification,
    });
  } catch (error) {
    console.error("Send notification error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get User Notifications
app.get("/api/notifications", authenticateToken, async (req, res) => {
  try {
    const { isRead } = req.query;

    const where = { userId: req.user.id };
    if (isRead !== undefined) where.isRead = isRead === "true";

    const notifications = await prisma.userNotification.findMany({
      where,
      orderBy: { createdAt: "desc" },
    });

    res.json({ notifications });
  } catch (error) {
    console.error("Get notifications error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Mark Notification as Read
app.put("/api/notifications/:id/read", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const notification = await prisma.userNotification.findUnique({
      where: { id },
      select: { userId: true },
    });

    if (!notification) {
      return res.status(404).json({ error: "Notification not found" });
    }

    if (notification.userId !== req.user.id) {
      return res
        .status(403)
        .json({ error: "Not authorized to update this notification" });
    }

    const updatedNotification = await prisma.userNotification.update({
      where: { id },
      data: {
        isRead: true,
        readAt: new Date(),
      },
    });

    res.json({
      message: "Notification marked as read",
      notification: updatedNotification,
    });
  } catch (error) {
    console.error("Mark notification read error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ========================================
// SYSTEM SETTINGS ROUTES
// ========================================

// Get System Settings
app.get("/api/admin/settings", authenticateAdmin, async (req, res) => {
  try {
    const { category } = req.query;

    const where = {};
    if (category) where.category = category;

    const settings = await prisma.systemSetting.findMany({
      where,
      orderBy: { category: "asc" },
    });

    res.json({ settings });
  } catch (error) {
    console.error("Get settings error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Update System Setting
app.put("/api/admin/settings/:key", authenticateAdmin, async (req, res) => {
  try {
    const { key } = req.params;
    const { value, description } = req.body;

    if (!value) {
      return res.status(400).json({ error: "Value is required" });
    }

    const setting = await prisma.systemSetting.upsert({
      where: { key },
      update: {
        value,
        description,
        updatedBy: req.admin.id,
        updatedAt: new Date(),
      },
      create: {
        key,
        value,
        description,
        category: "SYSTEM_CONFIGURATION",
        updatedBy: req.admin.id,
      },
    });

    res.json({
      message: "Setting updated successfully",
      setting,
    });
  } catch (error) {
    console.error("Update setting error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ========================================
// ERROR HANDLING MIDDLEWARE
// ========================================

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

// 404 handler
app.use("*", (req, res) => {
  res.status(404).json({ error: "Route not found" });
});

// ========================================
// START SERVER
// ========================================

app.listen(PORT, () => {
  console.log(`Badbaado Blood Bank Backend Server running on port ${PORT}`);
  console.log(`Database: PostgreSQL + Prisma`);
  console.log(`Authentication: JWT`);
  console.log(`Environment: ${process.env.NODE_ENV || "development"}`);
});

// Graceful shutdown
process.on("SIGINT", async () => {
  console.log("\n🛑 Shutting down server...");
  await prisma.$disconnect();
  process.exit(0);
});

module.exports = app;
