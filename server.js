
require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();

// Middleware
app.use(express.json({ limit: "1mb" }));

// Website connection permissions
const allowedOrigins = [
  "https://rohit7257.github.io",
  "http://localhost:5500",
  "http://127.0.0.1:5500",
  "http://localhost:5173"
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error("Origin not allowed"));
  }
}));

// Serve frontend website from public folder
app.use(express.static(path.join(__dirname, "public")));

// Citizen database structure
const citizenSchema = new mongoose.Schema({
  citizenId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  fatherName: String,
  dob: String,
  aadhaarMasked: String,
  house: String,
  block: String,
  village: String,
  city: String,
  pincode: String,
  address: String,
  panchayat: String,
  ward: String,
  mobile: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true, select: false }
}, { timestamps: true });

const Citizen = mongoose.model("Citizen", citizenSchema);

// Safe citizen information
function safeCitizen(citizen) {
  return {
    id: citizen._id,
    citizenId: citizen.citizenId,
    name: citizen.name,
    fatherName: citizen.fatherName,
    mobile: citizen.mobile,
    email: citizen.email,
    address: citizen.address,
    panchayat: citizen.panchayat,
    ward: citizen.ward,
    aadhaarMasked: citizen.aadhaarMasked
  };
}

// Create login token
function createToken(id, role) {
  return jwt.sign(
    { id: String(id), role },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

// Home route - show complete website
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "Nal Jal Yojana API is working",
    database: mongoose.connection.readyState === 1
      ? "Connected"
      : "Disconnected"
  });
});

// Citizen Registration
app.post("/api/auth/register", async (req, res) => {
  try {
    const {
      name, fatherName, dob, aadhaar,
      house, block, village, city, pincode,
      panchayat, ward, mobile, email, password
    } = req.body;

    if (
      !name || !fatherName || !dob ||
      !house || !block || !village ||
      !city || !pincode || !panchayat ||
      !ward || !mobile || !password
    ) {
      return res.status(400).json({
        success: false,
        message: "Please fill all required fields"
      });
    }

    if (!/^[0-9]{10}$/.test(String(mobile))) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid 10 digit mobile number"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 6 characters"
      });
    }

    if (aadhaar && !/^[0-9]{12}$/.test(String(aadhaar))) {
      return res.status(400).json({
        success: false,
        message: "Aadhaar must contain 12 digits"
      });
    }

    const finalEmail = String(email || `${mobile}@naljal.user`)
      .trim()
      .toLowerCase();

    const existing = await Citizen.findOne({
      $or: [
        { mobile: String(mobile) },
        { email: finalEmail }
      ]
    });

    if (existing) {
      return res.status(409).json({
        success: false,
        message: "Mobile number or email is already registered"
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const citizen = await Citizen.create({
      citizenId: "NJ-" + Date.now(),
      name: String(name).trim(),
      fatherName: String(fatherName).trim(),
      dob,
      aadhaarMasked: aadhaar
        ? "XXXX-XXXX-" + String(aadhaar).slice(-4)
        : "",
      house,
      block,
      village,
      city,
      pincode,
      address: `मकान ${house}, ब्लॉक ${block}, ग्राम ${village}, पंचायत ${panchayat}, ${city} - ${pincode}`,
      panchayat,
      ward: String(ward).padStart(2, "0"),
      mobile: String(mobile),
      email: finalEmail,
      passwordHash
    });

    const token = createToken(citizen._id, "citizen");

    res.status(201).json({
      success: true,
      message: "Registration successful",
      token,
      user: safeCitizen(citizen)
    });

  } catch (error) {
    console.error("Registration error:", error.message);

    res.status(500).json({
      success: false,
      message: "Registration failed"
    });
  }
});

// Citizen Login
app.post("/api/auth/citizen-login", async (req, res) => {
  try {
    const { mobileOrEmail, password } = req.body;

    if (!mobileOrEmail || !password) {
      return res.status(400).json({
        success: false,
        message: "Mobile/email and password are required"
      });
    }

    const loginValue = String(mobileOrEmail)
      .trim()
      .toLowerCase();

    const citizen = await Citizen.findOne({
      $or: [
        { mobile: loginValue },
        { email: loginValue }
      ]
    }).select("+passwordHash");

    if (!citizen) {
      return res.status(401).json({
        success: false,
        message: "Invalid mobile/email or password"
      });
    }

    const validPassword = await bcrypt.compare(
      password,
      citizen.passwordHash
    );

    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: "Invalid mobile/email or password"
      });
    }

    const token = createToken(citizen._id, "citizen");

    res.json({
      success: true,
      message: "Login successful",
      token,
      user: safeCitizen(citizen)
    });

  } catch (error) {
    console.error("Citizen login error:", error.message);

    res.status(500).json({
      success: false,
      message: "Login failed"
    });
  }
});

// Admin Login
app.post("/api/auth/admin-login", (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      !process.env.ADMIN_EMAIL ||
      !process.env.ADMIN_PASSWORD ||
      !process.env.JWT_SECRET
    ) {
      return res.status(500).json({
        success: false,
        message: "Admin environment settings are missing"
      });
    }

    const validEmail =
      String(email || "").trim().toLowerCase() ===
      process.env.ADMIN_EMAIL.trim().toLowerCase();

    const validPassword =
      password === process.env.ADMIN_PASSWORD;

    if (!validEmail || !validPassword) {
      return res.status(401).json({
        success: false,
        message: "Invalid admin credentials"
      });
    }

    const admin = {
      role: "admin",
      email: process.env.ADMIN_EMAIL,
      name: "विभागीय नोडल अधिकारी",
      division: "सदर ग्रामीण मंडल"
    };

    const token = createToken("admin", "admin");

    res.json({
      success: true,
      message: "Admin login successful",
      token,
      user: admin
    });

  } catch (error) {
    console.error("Admin login error:", error.message);

    res.status(500).json({
      success: false,
      message: "Admin login failed"
    });
  }
});

// Start server
const PORT = process.env.PORT || 5000;

async function startServer() {
  try {
    if (!process.env.MONGODB_URI || !process.env.JWT_SECRET) {
      throw new Error("MONGODB_URI or JWT_SECRET is missing in .env");
    }

    await mongoose.connect(process.env.MONGODB_URI);

    console.log("MongoDB Connected Successfully!");

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });

  } catch (error) {
    console.error("Server Error:", error.message);
    process.exit(1);
  }
}

startServer();
