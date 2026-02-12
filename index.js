import "dotenv/config";
import bodyParser from "body-parser";
import express from "express";
import pg from "pg";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import bcrypt from "bcrypt";

const app = express();
const port = 3000;
const saltRounds = 10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
// app.use(express.static(path.join(__dirname, "public")));

// static files

// Session Management
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 1000 * 60 * 60 * 24 }, // 1 day session
  }),
);

app.use(passport.initialize());
app.use(passport.session());

// DB Connection
const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
  ssl: { rejectUnauthorized: false },
});
db.connect();

// --- HELPER FUNCTIONS ---
function processUserName(user) {
  if (!user) return null;

  let displayName = user.name || user.gmail;
  try {
    // Check if name is a JSON string
    if (typeof user.name === "string" && user.name.startsWith("{")) {
      const nameObj = JSON.parse(user.name);
      displayName = nameObj.givenName || nameObj.name || user.gmail;
    } else if (typeof user.name === "object" && user.name !== null) {
      displayName = user.name.givenName || user.name.name || user.gmail;
    }
  } catch (e) {
    // If parsing fails, use the name as is or fallback to email
    displayName = user.name || user.gmail;
  }

  return {
    ...user,
    displayName: displayName,
    isAdmin: isAdmin(user),
  };
}

// Admin check function - checks if user email is in admin list
function isAdmin(user) {
  if (!user) return false;
  const adminEmails = (process.env.ADMIN_EMAILS || "")
    .split(",")
    .map((email) => email.trim().toLowerCase());
  const userEmail = (user.gmail || "").toLowerCase();
  return adminEmails.includes(userEmail) || user.is_admin === true;
}

// Verify admin password
function verifyAdminPassword(password) {
  const adminPassword = process.env.ADMIN_PASSWORD || "";
  return adminPassword && password === adminPassword;
}

// Admin middleware
function requireAdmin(req, res, next) {
  if (req.isAuthenticated() && isAdmin(req.user)) {
    return next();
  }
  res.status(403).send("Access denied. Admin privileges required.");
}

// --- ROUTES ---

app.get("/", (req, res) => {
  res.render("index.ejs");
});

app.get("/login", (req, res) => {
  if (req.isAuthenticated()) {
    if (isAdmin(req.user)) {
      res.redirect("/admin");
    } else {
      res.redirect("/expense");
    }
  } else {
    const error = req.query.error || "";
    const message = req.query.message || "";
    res.render("login.ejs", { error, message });
  }
});

app.get("/register", (req, res) => {
  if (req.isAuthenticated()) {
    if (isAdmin(req.user)) {
      res.redirect("/admin");
    } else {
      res.redirect("/expense");
    }
  } else {
    const error = req.query.error || "";
    const message = req.query.message || "";
    res.render("register.ejs", { error, message });
  }
});

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect("/");
  });
});

// --- DASHBOARD ROUTE (The Main Logic) ---
app.get("/expense", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const userId = req.user.id;

      // Fetch all transactions for the user, sorted by date (newest first)
      const result = await db.query(
        "SELECT * FROM expense WHERE user_id = $1 ORDER BY created_at DESC",
        [userId],
      );

      const transactions = result.rows;

      // Calculate Totals
      let totalIncome = 0;
      let totalExpense = 0;
      let totalReceivable = 0;
      let totalPayable = 0;

      // Prepare Data for Charts
      // We'll create a simple map for categories or monthly data here
      // For this example, let's group expenses by month for the chart
      const chartData = {};

      transactions.forEach((t) => {
        const amount = parseFloat(t.amount_rs);

        if (t.type === "income") totalIncome += amount;
        else if (t.type === "expense") {
          totalExpense += amount;

          // Chart Data Logic (Grouping by Month-Year)
          const date = new Date(t.created_at);
          const monthYear = date.toLocaleString("default", {
            month: "short",
            year: "2-digit",
          });
          if (chartData[monthYear]) {
            chartData[monthYear] += amount;
          } else {
            chartData[monthYear] = amount;
          }
        } else if (t.type === "receivable") totalReceivable += amount;
        else if (t.type === "payable") totalPayable += amount;
      });

      const totalBalance = totalIncome - totalExpense;

      // Process user name to extract givenName if stored as object
      const processedUser = processUserName(req.user);

      res.render("expense.ejs", {
        user: processedUser,
        transactions: transactions,
        totals: {
          income: totalIncome.toFixed(2),
          expense: totalExpense.toFixed(2),
          balance: totalBalance.toFixed(2),
          receivable: totalReceivable.toFixed(2),
          payable: totalPayable.toFixed(2),
        },
        chartLabels: JSON.stringify(Object.keys(chartData)),
        chartValues: JSON.stringify(Object.values(chartData)),
      });
    } catch (err) {
      console.error("Expense dashboard error:", err);
      res.redirect(
        "/login?error=server&message=" +
          encodeURIComponent("Error loading dashboard. Please try again."),
      );
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/add-expense", (req, res) => {
  if (req.isAuthenticated()) {
    const processedUser = processUserName(req.user);
    res.render("add-expense.ejs", { user: processedUser });
  } else {
    res.redirect("/login");
  }
});

app.post("/add-expense", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const { expenseDate, description, transfer_to, amount, type } = req.body;
      const user_id = req.user.id;

      // Validation
      if (!description || !transfer_to || !amount || !type || !expenseDate) {
        return res.redirect(
          "/add-expense?error=validation&message=" +
            encodeURIComponent("All fields are required"),
        );
      }

      if (isNaN(parseFloat(amount)) || parseFloat(amount) <= 0) {
        return res.redirect(
          "/add-expense?error=validation&message=" +
            encodeURIComponent("Amount must be a positive number"),
        );
      }

      await db.query(
        "INSERT INTO expense(description, transfer_to, amount_rs, created_at, user_id, type) VALUES($1,$2,$3,$4,$5,$6)",
        [description, transfer_to, amount, expenseDate, user_id, type],
      );
      res.redirect(
        "/expense?success=true&message=" +
          encodeURIComponent("Transaction added successfully!"),
      );
    } catch (error) {
      console.error("Error adding expense:", error);
      res.redirect(
        "/add-expense?error=server&message=" +
          encodeURIComponent("Error adding transaction. Please try again."),
      );
    }
  } else {
    res.redirect(
      "/login?error=auth&message=" +
        encodeURIComponent("Please login to continue"),
    );
  }
});

// --- ADMIN ROUTES ---

// Admin Dashboard
app.get("/admin", requireAdmin, async (req, res) => {
  try {
    // Get total users count
    const usersCount = await db.query("SELECT COUNT(*) as count FROM users");
    const totalUsers = parseInt(usersCount.rows[0].count);

    // Get total transactions count
    const transactionsCount = await db.query(
      "SELECT COUNT(*) as count FROM expense",
    );
    const totalTransactions = parseInt(transactionsCount.rows[0].count);

    // Get total amount of all transactions
    const totalAmountResult = await db.query(
      "SELECT SUM(amount_rs) as total FROM expense",
    );
    const totalAmount = parseFloat(totalAmountResult.rows[0].total || 0);

    // Get transactions by type
    const incomeResult = await db.query(
      "SELECT SUM(amount_rs) as total FROM expense WHERE type = 'income'",
    );
    const expenseResult = await db.query(
      "SELECT SUM(amount_rs) as total FROM expense WHERE type = 'expense'",
    );
    const receivableResult = await db.query(
      "SELECT SUM(amount_rs) as total FROM expense WHERE type = 'receivable'",
    );
    const payableResult = await db.query(
      "SELECT SUM(amount_rs) as total FROM expense WHERE type = 'payable'",
    );

    const totalIncome = parseFloat(incomeResult.rows[0].total || 0);
    const totalExpense = parseFloat(expenseResult.rows[0].total || 0);
    const totalReceivable = parseFloat(receivableResult.rows[0].total || 0);
    const totalPayable = parseFloat(payableResult.rows[0].total || 0);

    // Get recent transactions (last 10)
    const recentTransactions = await db.query(`
      SELECT e.*, u.name as user_name, u.gmail as user_email 
      FROM expense e 
      JOIN users u ON e.user_id = u.id 
      ORDER BY e.created_at DESC 
      LIMIT 10
    `);

    // Get users with transaction counts
    const usersWithStats = await db.query(`
      SELECT 
        u.id, 
        u.name, 
        u.gmail, 
        u.ph_no,
        COUNT(e.id) as transaction_count,
        COALESCE(SUM(e.amount_rs), 0) as total_amount
      FROM users u
      LEFT JOIN expense e ON u.id = e.user_id
      GROUP BY u.id, u.name, u.gmail, u.ph_no
      ORDER BY transaction_count DESC
      LIMIT 5
    `);

    const processedUser = processUserName(req.user);

    res.render("admin/dashboard.ejs", {
      user: processedUser,
      stats: {
        totalUsers,
        totalTransactions,
        totalAmount: totalAmount.toFixed(2),
        totalIncome: totalIncome.toFixed(2),
        totalExpense: totalExpense.toFixed(2),
        totalReceivable: totalReceivable.toFixed(2),
        totalPayable: totalPayable.toFixed(2),
        netBalance: (totalIncome - totalExpense).toFixed(2),
      },
      recentTransactions: recentTransactions.rows,
      topUsers: usersWithStats.rows,
    });
  } catch (err) {
    console.error("Admin dashboard error:", err);
    res.status(500).send("Error loading admin dashboard");
  }
});

// Admin Users List
app.get("/admin/users", requireAdmin, async (req, res) => {
  try {
    const search = req.query.search || "";
    let users;

    if (search) {
      users = await db.query(
        `
        SELECT 
          u.*,
          COUNT(e.id) as transaction_count,
          COALESCE(SUM(CASE WHEN e.type = 'income' THEN e.amount_rs ELSE 0 END), 0) as total_income,
          COALESCE(SUM(CASE WHEN e.type = 'expense' THEN e.amount_rs ELSE 0 END), 0) as total_expense
        FROM users u
        LEFT JOIN expense e ON u.id = e.user_id
        WHERE u.name ILIKE $1 OR u.gmail ILIKE $1
        GROUP BY u.id
        ORDER BY u.id DESC
      `,
        [`%${search}%`],
      );
    } else {
      users = await db.query(`
        SELECT 
          u.*,
          COUNT(e.id) as transaction_count,
          COALESCE(SUM(CASE WHEN e.type = 'income' THEN e.amount_rs ELSE 0 END), 0) as total_income,
          COALESCE(SUM(CASE WHEN e.type = 'expense' THEN e.amount_rs ELSE 0 END), 0) as total_expense
        FROM users u
        LEFT JOIN expense e ON u.id = e.user_id
        GROUP BY u.id
        ORDER BY u.id DESC
      `);
    }

    const processedUser = processUserName(req.user);

    res.render("admin/users.ejs", {
      user: processedUser,
      currentUserId: req.user.id,
      users: users.rows,
      search: search,
    });
  } catch (err) {
    console.error("Admin users error:", err);
    res.status(500).send("Error loading users");
  }
});

// Delete User
app.post("/admin/users/delete/:id", requireAdmin, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);

    if (isNaN(userId)) {
      return res.status(400).json({ error: "Invalid user ID" });
    }

    // Prevent admin from deleting themselves
    if (userId === req.user.id) {
      return res
        .status(400)
        .json({ error: "You cannot delete your own account" });
    }

    // Check if user exists
    const userCheck = await db.query("SELECT * FROM users WHERE id = $1", [
      userId,
    ]);
    if (userCheck.rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    // Delete user's transactions first (due to foreign key constraint)
    await db.query("DELETE FROM expense WHERE user_id = $1", [userId]);

    // Delete user
    await db.query("DELETE FROM users WHERE id = $1", [userId]);

    res.json({ success: true, message: "User deleted successfully" });
  } catch (err) {
    console.error("Delete user error:", err);
    res.status(500).json({ error: "Error deleting user. Please try again." });
  }
});

// Admin All Transactions
app.get("/admin/transactions", requireAdmin, async (req, res) => {
  try {
    const search = req.query.search || "";
    const typeFilter = req.query.type || "";
    const page = parseInt(req.query.page) || 1;
    const limit = 50;
    const offset = (page - 1) * limit;

    let query = `
      SELECT 
        e.*,
        u.name as user_name,
        u.gmail as user_email
      FROM expense e
      JOIN users u ON e.user_id = u.id
      WHERE 1=1
    `;
    const params = [];
    let paramCount = 1;

    if (search) {
      query += ` AND (e.description ILIKE $${paramCount} OR u.name ILIKE $${paramCount} OR u.gmail ILIKE $${paramCount} OR e.transfer_to ILIKE $${paramCount})`;
      params.push(`%${search}%`);
      paramCount++;
    }

    if (typeFilter) {
      query += ` AND e.type = $${paramCount}`;
      params.push(typeFilter);
      paramCount++;
    }

    query += ` ORDER BY e.created_at DESC LIMIT $${paramCount} OFFSET $${
      paramCount + 1
    }`;
    params.push(limit, offset);

    const transactions = await db.query(query, params);

    // Get total count for pagination
    let countQuery = `
      SELECT COUNT(*) as total
      FROM expense e
      JOIN users u ON e.user_id = u.id
      WHERE 1=1
    `;
    const countParams = [];
    let countParamCount = 1;

    if (search) {
      countQuery += ` AND (e.description ILIKE $${countParamCount} OR u.name ILIKE $${countParamCount} OR u.gmail ILIKE $${countParamCount} OR e.transfer_to ILIKE $${countParamCount})`;
      countParams.push(`%${search}%`);
      countParamCount++;
    }

    if (typeFilter) {
      countQuery += ` AND e.type = $${countParamCount}`;
      countParams.push(typeFilter);
      countParamCount++;
    }

    const totalResult = await db.query(countQuery, countParams);
    const totalTransactions = parseInt(totalResult.rows[0].total);
    const totalPages = Math.ceil(totalTransactions / limit);

    // Calculate totals
    let totalsQuery = `
      SELECT 
        COUNT(*) as count,
        SUM(amount_rs) as total_amount,
        SUM(CASE WHEN type = 'income' THEN amount_rs ELSE 0 END) as total_income,
        SUM(CASE WHEN type = 'expense' THEN amount_rs ELSE 0 END) as total_expense,
        SUM(CASE WHEN type = 'receivable' THEN amount_rs ELSE 0 END) as total_receivable,
        SUM(CASE WHEN type = 'payable' THEN amount_rs ELSE 0 END) as total_payable
      FROM expense e
      JOIN users u ON e.user_id = u.id
      WHERE 1=1
    `;

    if (search) {
      totalsQuery += ` AND (e.description ILIKE $1 OR u.name ILIKE $1 OR u.gmail ILIKE $1 OR e.transfer_to ILIKE $1)`;
    }

    if (typeFilter && !search) {
      totalsQuery += ` AND e.type = $1`;
    } else if (typeFilter && search) {
      totalsQuery += ` AND e.type = $2`;
    }

    const totalsParams = search ? [`%${search}%`] : [];
    if (typeFilter && !search) {
      totalsParams.push(typeFilter);
    } else if (typeFilter && search) {
      totalsParams.push(typeFilter);
    }

    const totalsResult = await db.query(
      totalsQuery,
      totalsParams.length > 0 ? totalsParams : null,
    );

    const processedUser = processUserName(req.user);

    res.render("admin/transactions.ejs", {
      user: processedUser,
      transactions: transactions.rows,
      search: search,
      typeFilter: typeFilter,
      currentPage: page,
      totalPages: totalPages,
      totalTransactions: totalTransactions,
      totals: totalsResult.rows[0],
    });
  } catch (err) {
    console.error("Admin transactions error:", err);
    res.status(500).send("Error loading transactions");
  }
});

// Delete Transaction
app.post("/admin/transactions/delete/:id", requireAdmin, async (req, res) => {
  try {
    const transactionId = parseInt(req.params.id);

    if (isNaN(transactionId)) {
      return res.status(400).json({ error: "Invalid transaction ID" });
    }

    // Check if transaction exists
    const transactionCheck = await db.query(
      "SELECT * FROM expense WHERE id = $1",
      [transactionId],
    );
    if (transactionCheck.rows.length === 0) {
      return res.status(404).json({ error: "Transaction not found" });
    }

    await db.query("DELETE FROM expense WHERE id = $1", [transactionId]);
    res.json({ success: true, message: "Transaction deleted successfully" });
  } catch (err) {
    console.error("Delete transaction error:", err);
    res
      .status(500)
      .json({ error: "Error deleting transaction. Please try again." });
  }
});

// Admin Statistics
app.get("/admin/stats", requireAdmin, async (req, res) => {
  try {
    // Monthly statistics
    const monthlyStats = await db.query(`
      SELECT 
        TO_CHAR(created_at, 'YYYY-MM') as month,
        COUNT(*) as transaction_count,
        SUM(amount_rs) as total_amount,
        SUM(CASE WHEN type = 'income' THEN amount_rs ELSE 0 END) as income,
        SUM(CASE WHEN type = 'expense' THEN amount_rs ELSE 0 END) as expense
      FROM expense
      GROUP BY TO_CHAR(created_at, 'YYYY-MM')
      ORDER BY month DESC
      LIMIT 12
    `);

    // Top users by transaction count
    const topUsersByTransactions = await db.query(`
      SELECT 
        u.id,
        u.name,
        u.gmail,
        COUNT(e.id) as transaction_count,
        SUM(e.amount_rs) as total_amount
      FROM users u
      JOIN expense e ON u.id = e.user_id
      GROUP BY u.id, u.name, u.gmail
      ORDER BY transaction_count DESC
      LIMIT 10
    `);

    // Top users by amount
    const topUsersByAmount = await db.query(`
      SELECT 
        u.id,
        u.name,
        u.gmail,
        COUNT(e.id) as transaction_count,
        SUM(e.amount_rs) as total_amount
      FROM users u
      JOIN expense e ON u.id = e.user_id
      GROUP BY u.id, u.name, u.gmail
      ORDER BY total_amount DESC
      LIMIT 10
    `);

    // Transaction type distribution
    const typeDistribution = await db.query(`
      SELECT 
        type,
        COUNT(*) as count,
        SUM(amount_rs) as total_amount
      FROM expense
      GROUP BY type
      ORDER BY count DESC
    `);

    const processedUser = processUserName(req.user);

    res.render("admin/stats.ejs", {
      user: processedUser,
      monthlyStats: monthlyStats.rows,
      topUsersByTransactions: topUsersByTransactions.rows,
      topUsersByAmount: topUsersByAmount.rows,
      typeDistribution: typeDistribution.rows,
    });
  } catch (err) {
    console.error("Admin stats error:", err);
    res.status(500).send("Error loading statistics");
  }
});

// --- AUTHENTICATION HANDLERS ---

app.post("/register", async (req, res) => {
  try {
    const { name, username, password, phno } = req.body;

    // Validation
    if (!name || !username || !password) {
      return res.redirect(
        "/register?error=validation&message=" +
          encodeURIComponent("All fields are required"),
      );
    }

    if (password.length < 6) {
      return res.redirect(
        "/register?error=validation&message=" +
          encodeURIComponent("Password must be at least 6 characters"),
      );
    }

    const check = await db.query("SELECT * FROM users WHERE gmail = $1", [
      username,
    ]);
    if (check.rows.length > 0) {
      return res.redirect(
        "/register?error=exists&message=" +
          encodeURIComponent("Email already registered. Please login instead."),
      );
    }

    bcrypt.hash(password, saltRounds, async (err, hash) => {
      if (err) {
        console.error("Password hashing error:", err);
        return res.redirect(
          "/register?error=server&message=" +
            encodeURIComponent("Server error. Please try again."),
        );
      }

      try {
        const result = await db.query(
          "INSERT INTO users(name, gmail, password, ph_no) VALUES($1,$2,$3,$4) RETURNING *",
          [name, username, hash, phno],
        );

        req.login(result.rows[0], (err) => {
          if (err) {
            console.error("Auto-login error:", err);
            return res.redirect(
              "/login?error=session&message=" +
                encodeURIComponent("Registration successful! Please login."),
            );
          }

          // Check if user is admin and redirect accordingly
          if (isAdmin(result.rows[0])) {
            return res.redirect("/admin");
          }
          res.redirect("/expense");
        });
      } catch (dbError) {
        console.error("Database error:", dbError);
        return res.redirect(
          "/register?error=server&message=" +
            encodeURIComponent("Database error. Please try again."),
        );
      }
    });
  } catch (err) {
    console.error("Registration error:", err);
    res.redirect(
      "/register?error=server&message=" +
        encodeURIComponent("An unexpected error occurred. Please try again."),
    );
  }
});

// Admin Login Page
app.get("/admin/login", (req, res) => {
  if (req.isAuthenticated() && isAdmin(req.user)) {
    res.redirect("/admin");
  } else {
    const error = req.query.error || "";
    const message = req.query.message || "";
    res.render("admin/login.ejs", { error, message });
  }
});

// Admin Login Handler
app.post("/admin/login", async (req, res) => {
  try {
    const { username, adminPassword } = req.body;

    // Validate admin password
    if (!adminPassword || !verifyAdminPassword(adminPassword)) {
      return res.redirect(
        "/admin/login?error=admin&message=" +
          encodeURIComponent("Invalid admin password"),
      );
    }

    // Check if email is in admin list
    if (!isAdmin({ gmail: username })) {
      return res.redirect(
        "/admin/login?error=admin&message=" +
          encodeURIComponent("This email is not registered as an admin"),
      );
    }

    // Find or create user by email
    try {
      let result = await db.query("SELECT * FROM users WHERE gmail = $1", [
        username,
      ]);
      let user;

      if (result.rows.length === 0) {
        // Auto-create admin user if they don't exist
        // Extract name from email (part before @) or use "Admin User"
        const nameFromEmail = username.split("@")[0];
        const adminName =
          nameFromEmail.charAt(0).toUpperCase() + nameFromEmail.slice(1);

        // Create user with a default password (admin can change it later if needed)
        // Using a secure random password hash
        const defaultPassword = "admin_temp_" + Date.now();

        // Use bcrypt.hash with promise pattern
        const hashedPassword = await new Promise((resolve, reject) => {
          bcrypt.hash(defaultPassword, saltRounds, (err, hash) => {
            if (err) reject(err);
            else resolve(hash);
          });
        });

        const newUser = await db.query(
          "INSERT INTO users(name, gmail, password) VALUES($1, $2, $3) RETURNING *",
          [adminName, username, hashedPassword],
        );

        user = newUser.rows[0];
        console.log(`Auto-created admin user: ${username}`);
      } else {
        user = result.rows[0];
      }

      // Log in the admin user
      req.logIn(user, (err) => {
        if (err) {
          console.error("Session error:", err);
          return res.redirect(
            "/admin/login?error=session&message=" +
              encodeURIComponent("Session error. Please try again."),
          );
        }
        return res.redirect("/admin");
      });
    } catch (dbError) {
      console.error("Database error during admin login:", dbError);
      return res.redirect(
        "/admin/login?error=server&message=" +
          encodeURIComponent("Database error. Please try again."),
      );
    }
  } catch (error) {
    console.error("Admin login route error:", error);
    res.redirect(
      "/admin/login?error=server&message=" +
        encodeURIComponent("An unexpected error occurred. Please try again."),
    );
  }
});

// Regular User Login
app.post("/login", async (req, res, next) => {
  try {
    // Regular user login - use passport authentication
    passport.authenticate("local", (err, user, info) => {
      if (err) {
        console.error("Login error:", err);
        return res.redirect(
          "/login?error=server&message=" +
            encodeURIComponent("Server error. Please try again."),
        );
      }

      if (!user) {
        return res.redirect(
          "/login?error=auth&message=" +
            encodeURIComponent("User not found or invalid password"),
        );
      }

      req.logIn(user, (err) => {
        if (err) {
          console.error("Session error:", err);
          return res.redirect(
            "/login?error=session&message=" +
              encodeURIComponent("Session error. Please try again."),
          );
        }

        // Check if user is admin and redirect accordingly
        if (isAdmin(user)) {
          return res.redirect("/admin");
        }
        return res.redirect("/expense");
      });
    })(req, res, next);
  } catch (error) {
    console.error("Login route error:", error);
    res.redirect(
      "/login?error=server&message=" +
        encodeURIComponent("An unexpected error occurred. Please try again."),
    );
  }
});

// Passport Strategies
passport.use(
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE gmail = $1", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        bcrypt.compare(password, user.password, (err, valid) => {
          if (err) return cb(err);
          if (valid) return cb(null, user);
          return cb(null, false);
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      return cb(err);
    }
  }),
);

// Google Auth (Keep your existing Google Strategy setup if credentials are in .env)
passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const result = await db.query("SELECT * FROM users WHERE gmail = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (name, gmail, password) VALUES ($1, $2, $3) RETURNING *",
            [profile.name.givenName, profile.email, "google"],
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    },
  ),
);

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] }),
);
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    // Check if user is admin and redirect accordingly
    if (isAdmin(req.user)) {
      return res.redirect("/admin");
    }
    res.redirect("/expense");
  },
);

passport.serializeUser((user, cb) => cb(null, user));
passport.deserializeUser((user, cb) => cb(null, user));

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
