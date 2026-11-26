
require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();

// Middleware
// Frontend documents are limited to 500 KB each.
app.use(express.json({ limit: "5mb" }));

const allowedOrigins = [
  "https://rohit7257.github.io",
  "https://jalmitra-api-gilo.onrender.com",
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

app.use(express.static(path.join(__dirname, "public")));

// --------------------------------------------------
// DATABASE MODELS
// --------------------------------------------------

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

// New connection applications
const applicationSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true, index: true },
  citizenId: { type: mongoose.Schema.Types.ObjectId, ref: "Citizen", required: true, index: true },
  applicantName: { type: String, required: true },
  fatherName: String,
  mobile: { type: String, required: true },
  email: String,
  aadhaar: String,
  panchayat: String,
  ward: String,
  address: String,
  connectionType: String,
  documents: {
    aadhaar: { type: mongoose.Schema.Types.Mixed, default: null },
    voterId: { type: mongoose.Schema.Types.Mixed, default: null },
    pan: { type: mongoose.Schema.Types.Mixed, default: null }
  },
  date: String,
  status: {
    type: String,
    default: "निरीक्षण हेतु लंबित (Pending)"
  },
  remarks: { type: String, default: "" }
}, { timestamps: true });

const Application = mongoose.model("Application", applicationSchema);

// Citizen grievances
const grievanceSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true, index: true },
  citizenId: { type: mongoose.Schema.Types.ObjectId, ref: "Citizen", required: true, index: true },
  citizenName: String,
  fatherName: String,
  mobile: String,
  email: String,
  panchayat: String,
  ward: String,
  category: String,
  location: String,
  description: String,
  priority: String,
  status: {
    type: String,
    default: "नई शिकायत (Pending)"
  },
  assignedTo: { type: String, default: "" },
  remarks: { type: String, default: "" },
  date: String
}, { timestamps: true });

const Grievance = mongoose.model("Grievance", grievanceSchema);

// Public notices
const noticeSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true, index: true },
  title: { type: String, required: true },
  body: { type: String, required: true },
  date: String,
  createdBy: String
}, { timestamps: true });

const Notice = mongoose.model("Notice", noticeSchema);

// --------------------------------------------------
// COMMON HELPERS
// --------------------------------------------------

function safeCitizen(citizen) {
  return {
    id: String(citizen._id),
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

function createToken(id, role) {
  return jwt.sign(
    { id: String(id), role },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function today() {
  return new Date().toLocaleDateString("en-IN");
}

function makeId(prefix) {
  return `${prefix}-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
}

// Check JWT token
async function authenticate(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Please login first"
      });
    }

    const token = header.slice(7);
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.role === "admin") {
      req.user = {
        id: decoded.id,
        role: "admin"
      };
      return next();
    }

    if (decoded.role !== "citizen") {
      return res.status(401).json({
        success: false,
        message: "Invalid login role"
      });
    }

    const citizen = await Citizen.findById(decoded.id);

    if (!citizen) {
      return res.status(401).json({
        success: false,
        message: "Citizen account not found"
      });
    }

    req.user = {
      id: String(citizen._id),
      role: "citizen",
      citizen
    };

    next();

  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Session expired or invalid. Please login again."
    });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Admin access required"
    });
  }
  next();
}

function citizenOnly(req, res, next) {
  if (!req.user || req.user.role !== "citizen") {
    return res.status(403).json({
      success: false,
      message: "Citizen login required"
    });
  }
  next();
}

// Validate uploaded document data
function validateDocument(doc) {
  if (!doc) return true;

  const allowedTypes = [
    "application/pdf",
    "image/jpeg",
    "image/png",
    "image/webp"
  ];

  if (
    typeof doc !== "object" ||
    !allowedTypes.includes(doc.type) ||
    typeof doc.dataUrl !== "string" ||
    doc.dataUrl.length > 750000
  ) {
    return false;
  }

  return true;
}

// --------------------------------------------------
// WEBSITE AND HEALTH ROUTES
// --------------------------------------------------

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "Nal Jal Yojana API is working",
    database: mongoose.connection.readyState === 1
      ? "Connected"
      : "Disconnected"
  });
});

// --------------------------------------------------
// CITIZEN REGISTRATION
// --------------------------------------------------

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

    if (String(password).length < 6) {
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

// --------------------------------------------------
// CITIZEN LOGIN
// --------------------------------------------------

app.post("/api/auth/citizen-login", async (req, res) => {
  try {
    const { mobileOrEmail, password } = req.body;

    if (!mobileOrEmail || !password) {
      return res.status(400).json({
        success: false,
        message: "Mobile/email and password are required"
      });
    }

    const loginValue = String(mobileOrEmail).trim().toLowerCase();

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

// --------------------------------------------------
// ADMIN LOGIN
// --------------------------------------------------

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

// --------------------------------------------------
// NEW CONNECTION APPLICATION ROUTES
// --------------------------------------------------

// Citizen submits a new application
app.post("/api/applications", authenticate, citizenOnly, async (req, res) => {
  try {
    const citizen = req.user.citizen;
    const {
      id, applicantName, mobile, aadhaar,
      panchayat, ward, address, connectionType, documents
    } = req.body;

    if (
      !applicantName || !panchayat || !ward ||
      !address || !connectionType
    ) {
      return res.status(400).json({
        success: false,
        message: "Please fill all application fields"
      });
    }

    if (mobile && String(mobile) !== citizen.mobile) {
      return res.status(403).json({
        success: false,
        message: "Application mobile number must match your registered number"
      });
    }

    const docs = documents || {};

    if (
      !validateDocument(docs.aadhaar) ||
      !validateDocument(docs.voterId) ||
      !validateDocument(docs.pan)
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid document. Please upload PDF, JPG, PNG or WEBP up to 500 KB."
      });
    }

    const application = await Application.create({
      id: id || makeId("NJ-APP"),
      citizenId: citizen._id,
      applicantName: citizen.name,
      fatherName: citizen.fatherName,
      mobile: citizen.mobile,
      email: citizen.email,

      // Store masked Aadhaar only, not the full Aadhaar number.
      aadhaar: aadhaar && /^[0-9]{12}$/.test(String(aadhaar))
        ? "XXXX-XXXX-" + String(aadhaar).slice(-4)
        : "",

      panchayat: citizen.panchayat || panchayat,
      ward: citizen.ward || ward,
      address,
      connectionType,
      documents: {
        aadhaar: docs.aadhaar || null,
        voterId: docs.voterId || null,
        pan: docs.pan || null
      },
      date: today(),
      status: "निरीक्षण हेतु लंबित (Pending)"
    });

    res.status(201).json({
      success: true,
      message: "Application submitted successfully",
      item: application
    });

  } catch (error) {
    console.error("Application submit error:", error.message);

    res.status(500).json({
      success: false,
      message: "Application could not be submitted"
    });
  }
});

// Admin sees all applications; citizen sees only own applications
app.get("/api/applications", authenticate, async (req, res) => {
  try {
    const filter = req.user.role === "admin"
      ? {}
      : { citizenId: req.user.id };

    const items = await Application.find(filter)
      .sort({ createdAt: -1 })
      .lean();

    res.json({ success: true, items });

  } catch (error) {
    console.error("Application fetch error:", error.message);

    res.status(500).json({
      success: false,
      message: "Applications could not be loaded"
    });
  }
});

// Admin approves or rejects an application
app.patch("/api/applications/:id", authenticate, adminOnly, async (req, res) => {
  try {
    const { status, remarks } = req.body;

    if (!status) {
      return res.status(400).json({
        success: false,
        message: "Application status is required"
      });
    }

    const item = await Application.findOneAndUpdate(
      { id: req.params.id },
      {
        $set: {
          status: String(status),
          remarks: String(remarks || "")
        }
      },
      { new: true, runValidators: true }
    );

    if (!item) {
      return res.status(404).json({
        success: false,
        message: "Application not found"
      });
    }

    res.json({
      success: true,
      message: "Application updated",
      item
    });

  } catch (error) {
    console.error("Application update error:", error.message);

    res.status(500).json({
      success: false,
      message: "Application update failed"
    });
  }
});

// --------------------------------------------------
// GRIEVANCE / COMPLAINT ROUTES
// --------------------------------------------------

// Citizen submits a complaint
app.post("/api/grievances", authenticate, citizenOnly, async (req, res) => {
  try {
    const citizen = req.user.citizen;
    const { category, location, description, priority } = req.body;

    if (!location || !description || !category) {
      return res.status(400).json({
        success: false,
        message: "Category, location and description are required"
      });
    }

    const item = await Grievance.create({
      id: makeId("NJ-GRV"),
      citizenId: citizen._id,
      citizenName: citizen.name,
      fatherName: citizen.fatherName,
      mobile: citizen.mobile,
      email: citizen.email,
      panchayat: citizen.panchayat || "",
      ward: citizen.ward || "",
      category,
      location,
      description,
      priority: priority || "सामान्य (Normal)",
      status: "नई शिकायत (Pending)",
      assignedTo: "",
      remarks: "",
      date: today()
    });

    res.status(201).json({
      success: true,
      message: "Grievance registered successfully",
      item
    });

  } catch (error) {
    console.error("Grievance submit error:", error.message);

    res.status(500).json({
      success: false,
      message: "Grievance could not be registered"
    });
  }
});

// Admin sees all complaints; citizen sees only own complaints
app.get("/api/grievances", authenticate, async (req, res) => {
  try {
    const filter = req.user.role === "admin"
      ? {}
      : { citizenId: req.user.id };

    const items = await Grievance.find(filter)
      .sort({ createdAt: -1 })
      .lean();

    res.json({ success: true, items });

  } catch (error) {
    console.error("Grievance fetch error:", error.message);

    res.status(500).json({
      success: false,
      message: "Grievances could not be loaded"
    });
  }
});

// Admin updates complaint status
app.patch("/api/grievances/:id", authenticate, adminOnly, async (req, res) => {
  try {
    const { status, assignedTo, remarks } = req.body;

    if (!status) {
      return res.status(400).json({
        success: false,
        message: "Grievance status is required"
      });
    }

    const item = await Grievance.findOneAndUpdate(
      { id: req.params.id },
      {
        $set: {
          status: String(status),
          assignedTo: String(assignedTo || ""),
          remarks: String(remarks || "")
        }
      },
      { new: true, runValidators: true }
    );

    if (!item) {
      return res.status(404).json({
        success: false,
        message: "Grievance not found"
      });
    }

    res.json({
      success: true,
      message: "Grievance updated",
      item
    });

  } catch (error) {
    console.error("Grievance update error:", error.message);

    res.status(500).json({
      success: false,
      message: "Grievance update failed"
    });
  }
});

// --------------------------------------------------
// PUBLIC NOTICE ROUTES
// --------------------------------------------------

// Anyone can see the latest notice
app.get("/api/notices/latest", async (req, res) => {
  try {
    const item = await Notice.findOne()
      .sort({ createdAt: -1 })
      .lean();

    res.json({
      success: true,
      item: item || null
    });

  } catch (error) {
    console.error("Notice fetch error:", error.message);

    res.status(500).json({
      success: false,
      message: "Notice could not be loaded"
    });
  }
});

// Admin publishes a notice
app.post("/api/notices", authenticate, adminOnly, async (req, res) => {
  try {
    const { title, body } = req.body;

    if (!title || !body) {
      return res.status(400).json({
        success: false,
        message: "Notice title and message are required"
      });
    }

    const item = await Notice.create({
      id: makeId("NJ-NOTICE"),
      title: String(title).trim(),
      body: String(body).trim(),
      date: today(),
      createdBy: req.user.id
    });

    res.status(201).json({
      success: true,
      message: "Notice published successfully",
      item
    });

  } catch (error) {
    console.error("Notice publish error:", error.message);

    res.status(500).json({
      success: false,
      message: "Notice could not be published"
    });
  }
});

// --------------------------------------------------
// ERROR HANDLER
// --------------------------------------------------

app.use((err, req, res, next) => {
  console.error("Server middleware error:", err.message);

  if (err.message === "Origin not allowed") {
    return res.status(403).json({
      success: false,
      message: "Website origin not allowed"
    });
  }

  if (err.type === "entity.too.large") {
    return res.status(413).json({
      success: false,
      message: "Request is too large. Please check uploaded documents."
    });
  }

  res.status(500).json({
    success: false,
    message: "Internal server error"
  });
});

// --------------------------------------------------
// START SERVER
// --------------------------------------------------

const PORT = process.env.PORT || 5000;

async function startServer() {
  try {
    if (!process.env.MONGODB_URI || !process.env.JWT_SECRET) {
      throw new Error("MONGODB_URI or JWT_SECRET is missing in environment settings");
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
