    // server.js
    import dotenv from "dotenv";
dotenv.config();
    import helmet from "helmet";
    import rateLimit from "express-rate-limit";
    import express from "express";
    import mongoose from "mongoose";
    import cors from "cors";
    import bcrypt from "bcrypt";
    import jwt from "jsonwebtoken";
    import Transaction from "./models/Transaction.js";
    const PORT = process.env.PORT || 3000;
    const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";
    const JWT_EXPIRES = "6h";
    const SALT_ROUNDS = 10;

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests, please try again later."
});
    const app = express();
    app.set('trust proxy', 1);
    app.use(cors());
    app.use(express.json());
    app.use(express.static("public"));
    app.use(helmet());
    app.disable("x-powered-by");

mongoose.set("strictQuery", true);
console.log("ENV TEST:", process.env.MONGO);
console.log("DB NAME:", mongoose.connection.name);
console.log("DB HOST:", mongoose.connection.host);
mongoose.connect(process.env.MONGO, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log("MongoDB Connected ✅");
})  
.catch((err) => {
  console.error("MongoDB Error ❌:", err);
});

     
    // Middlewares
  
    // Schema
    const userSchema = new mongoose.Schema(
      {
        firstName: { type: String, required: true },
        lastName: { type: String, required: true },
        nationalId: { type: String, required: true },
        username: { type: String, required: true, unique: true },
        email: { type: String, required: true, unique: true },
        phone: { type: String, required: true },
        password: { type: String, required: true },
        dob: { type: Date, required: true },
        balance: { type: Number, default: 10000 },
        loginAttempts: { type: Number, default: 0 },
        lockUntil: { type: Date }
      },
      { timestamps: true }
    );

    const User = mongoose.model("User", userSchema);

    const cardSchema = new mongoose.Schema(
      {
        userId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
          required: true,
        },

        cardName: {
          type: String,
          required: true,
        },

        accountNumber: {
          type: String,
          required: true,
          validate: {
            validator: function (v) {
              return /^[0-9]{16}$/.test(v);
            },
            message: "Card number must be exactly 16 digits",
          },
        },

        cardType: {
          type: String,
          enum: ["debit", "credit"],
          required: true,
        },

        expiryDate: {
          type: String,
          required: true,
        },

        cvv: {
          type: String,
          required: true,
        },

        cardPassword: {
          type: String,
          required: true,
        },
      },
      { timestamps: true }
    );

    const Card = mongoose.model("Card", cardSchema);

    const contactSchema = new mongoose.Schema(
      {
        name: { type: String, required: true },
        phone: { type: String, required: true },
        email: { type: String, required: true },
        message: { type: String, required: true },
      },
      { timestamps: true }
    );

    const Contact = mongoose.model("Contact", contactSchema);

    // Helpers
    function validateEmail(email) {
      const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      return re.test(email);
    }

    function validateMobile(mobile) {
      const re = /^[0-9]{7,15}$/;
      return re.test(mobile);
    }

    // Register endpoint
    app.post("/register", async (req, res) => {
      console.log("recved data", req.body);

      try {
        const {
          firstName,
          lastName,
          nationalId,
          username,
          email,
          phone,
          password,
          dob,
        } = req.body;

        // National ID must be exactly 14 digits
        if (!/^\d{14}$/.test(nationalId)) {
          return res.status(400).json({
            message: "National ID must be exactly 14 digits",
          });
        }

        if (
          !firstName ||
          !lastName ||
          !nationalId ||
          !username ||
          !email ||
          !phone ||
          !password ||
          !dob
    ) {
      return res.status(400).json({ message: "All fields are required" });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ message: "Invalid email format" });
    }

    if (!validateMobile(phone)) {
      return res.status(400).json({ message: "Invalid mobile number" });
    }

    const existUser = await User.findOne({
      $or: [{ username }, { email }],
    });

    if (existUser) {
      return res
        .status(409)
        .json({ message: "Username or email already exists" });
    }

        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        const newUser = new User({
          firstName,
          lastName,
          nationalId,
          username,
          email,
          phone,
          password: hashedPassword,
          dob: new Date(dob),
        });

        const savedUser = await newUser.save();

        const { password: _p, __v, ...userSafe } = savedUser.toObject();

        return res.status(201).json({
          message: "login successfully ",
          user: userSafe,
        });
      
      }catch (err) {
      console.error("REGISTER ERROR:", err);
      res.status(500).json({
        message: "server error",
        error: err.message
      
      });
    }
    });   
    // -------- Login --------
    app.post("/login", async (req, res) => {
      try {
        const { username, password } = req.body;

        // 1️⃣ تحقق من الحقول
        if (!username || !password) {
          return res.status(400).json({ message: "all filde  required" });
        }

        // 2️⃣ دور على المستخدم بالـ username
        const user = await User.findOne({ username });
        if (!user) {
          return res
            .status(401)
            .json({ message: "error username or password" });
        }
        // 🔐 لو الحساب مقفول
        if (user.lockUntil && user.lockUntil > Date.now()) {
         return res.status(403).json({
          message: "Account locked. Try again after 1 hour."
  });
}

       const match = await bcrypt.compare(password, user.password);

if (!match) {

  user.loginAttempts += 1; // 🔢 نزود العداد

if (user.loginAttempts >= 4) {
  user.lockUntil = Date.now() + 60 * 60 * 1000;

  await user.save();

  return res.status(403).json({
    message: "Account locked due to multiple failed attempts. Try again after 1 hour."
  });
}

  await user.save();

  return res.status(401).json({
    message: "Invalid username or password"
  });
}

        // 4️⃣ إنشاء JWT
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
          
          expiresIn: JWT_EXPIRES,
        });
        // ✅ reset بعد نجاح login
          user.loginAttempts = 0;
           user.lockUntil = undefined;
            await user.save();

        // 5️⃣ رجّع بيانات آمنة
        const { password: _p, __v, ...userSafe } = user.toObject();

        return res.json({
          message: "login successfully",
          token,
          user: userSafe,
        });
      } catch (err) {
        return res.status(500).json({
          message: "server error",
          error: err.message,
        });
      }
    });

    app.get("/user/:id", async (req, res) => {
      try {
        const user = await User.findById(req.params.id).select("-password -__v");
        if (!user) return res.status(404).json({ message: "User not found" });
        res.json(user);
      } catch {
        res.status(500).json({ message: "Server error" });
      }
    });

    app.put("/user/:id", async (req, res) => {
      try {
        const updatedUser = await User.findByIdAndUpdate(req.params.id, req.body, {
          new: true,
          runValidators: true,
        });

        const { password, __v, ...safeUser } = updatedUser.toObject();
        res.json({ user: safeUser });
      } catch {
        res.status(500).json({ message: "error refreshing" });
      }
    });

    app.put("/change-password", async (req, res) => {
      const { userId, oldPass, newPass } = req.body;

      const user = await User.findById(userId);
      const match = await bcrypt.compare(oldPass, user.password);

      if (!match) return res.status(400).json({});

      user.password = await bcrypt.hash(newPass, SALT_ROUNDS);
      await user.save();

      res.json({ message: "ok" });
    });

    app.post("/transfer/check-card-password", async (req, res) => {
      const { userId, password } = req.body;

      try {
        const card = await Card.findOne({ userId });
        if (!card) return res.status(404).json({ message: "No card found" });

        const match = await bcrypt.compare(password, card.cardPassword);
        if (!match)
          return res.status(400).json({ message: "Incorrect card password" });

        res.json({ message: "ok" });
      } catch {
        res.status(500).json({ message: "server error " });
      }
    });

    app.post("/transfer/bank-transfer", async (req, res) => {

    const { userId, transferType, bank, beneficiaryName, beneficiaryAccount, amount } = req.body;

    try {

    const sender = await User.findById(userId);
    if (!sender)
    return res.status(404).json({ message: "Sender not found" });

    const transferAmount = Number(amount);

    if (sender.balance < transferAmount)
    return res.status(400).json({ message: "Insufficient balance" });


    // SAME BANK
    // SAME BANK
    if (transferType === "internal") {

    const receiverCard = await Card.findOne({
    accountNumber: beneficiaryAccount
    });

    if (!receiverCard)
    return res.status(404).json({ message: "Invalid account number" });

    const receiver = await User.findById(receiverCard.userId);

    // زيادة الرصيد للمستلم
    receiver.balance += Number(amount);
    await receiver.save();


    // تسجيل transaction للمستلم
    await Transaction.create({
    userId: receiver._id,
    type: "bank",
    amount,
    source: "Same Bank",
    direction: "in",
    senderName: sender.firstName + " " + sender.lastName
    });

    }


    // الخصم من المرسل
    sender.balance -= Number(amount);
    await sender.save();


    await Transaction.create({
    userId: sender._id,
    type: "bank",
    amount,
    source: transferType === "external" ? bank : "Same Bank",
    direction: "out",
    beneficiaryName,
    beneficiaryAccount
    });


    res.json({
    message: "Transfer successful",
    newBalance: sender.balance
    });

    } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
    }

    });

    // Wallet Transfer (one side only)
    app.post("/transfer/wallet-transfer", async (req, res) => {
      const { userId, walletNumber, amount } = req.body;

      if (!userId || !walletNumber || !amount)
        return res.status(400).json({ message: "incomplete data" });

      try {
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ message: "user not found" });

        if (user.balance < amount)
          return res.status(400).json({ message: "insufficient balance" });

        user.balance -= Number(amount);
        await user.save();

        await Transaction.create({
          userId: user._id,
          type: "wallet",
          amount,
          source: "Wallet",
          direction: "out",
          beneficiaryName: "Wallet Transfer",
          beneficiaryAccount: walletNumber,
        });

        res.json({ message: "conversion completed successfully", newBalance: user.balance });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "server error" });
      }
    });

    // Add Card
    app.post("/add-card", async (req, res) => {
      try {
        const { userId, cardName, accountNumber, cardType, expiryDate, cvv, cardPassword } =
          req.body;

        if (
          !userId ||
          !cardName ||
          !accountNumber ||
          !cardType ||
          !expiryDate ||
          !cvv ||
          !cardPassword
        ) {
          return res.status(400).json({ message: "all fields are required" });
        }

        if (!/^[0-9]{16}$/.test(accountNumber)) {
          return res.status(400).json({ message: "Card number must be exactly 16 digits" });
        }

        const hashedCardPassword = await bcrypt.hash(cardPassword, SALT_ROUNDS);

        const newCard = new Card({
          userId,
          cardName,
          accountNumber,
          cardType,
          expiryDate,
          cvv,
          cardPassword: hashedCardPassword,
        });

        await newCard.save();

        res.status(201).json({ message: "card was added successfuly" });
      } catch (err) {
        res.status(500).json({ message: "server error", error: err.message });
      }
    });

    // Get Card by UserId
    app.get("/card/:userId", async (req, res) => {
      try {
        const { userId } = req.params;

        const card = await Card.findOne({ userId });
        if (!card) return res.status(404).json({ message: "no user for this card" });

        const { cvv, cardPassword, __v, ...cardSafe } = card.toObject();
        res.json({ card: cardSafe });
      } catch (err) {
        res.status(500).json({ message: "server error", error: err.message });
      }
    });

    app.post("/atm/transaction", async (req, res) => {
      try {
        const { cardNumber, cardPassword, amount, type } = req.body;

        if (!cardNumber || !cardPassword || !amount || !type)
          return res.status(400).json({ message: "uncompleted data" });

        const cleanCardNumber = cardNumber.replace(/\s|-/g, "");
        const card = await Card.findOne({ accountNumber: cleanCardNumber });
        if (!card) return res.status(404).json({ message: "not found cerd" });

        const match = await bcrypt.compare(cardPassword, card.cardPassword);
        if (!match) return res.status(401).json({ message: "Invalid PIN." });

        const user = await User.findById(card.userId);
        if (!user) return res.status(404).json({ message: "User not found" });

        if (type === "withdrawal") {
          if (user.balance < amount)
            return res.status(400).json({ message: "Insufficient balance" });
          user.balance -= Number(amount);
        }

        if (type === "deposit") {
          user.balance += Number(amount);
        }

        await user.save();

        await Transaction.create({
          userId: user._id,
          type,
          amount,
          source: "ATM",
        });

        res.json({
          message: "operation was completed successfully",
          newBalance: user.balance,
        });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "server error" });
      }
    });

    app.get("/transactions/:userId", async (req, res) => {
      try {
        const { userId } = req.params;

        const transactions = await Transaction.find({ userId }).sort({ createdAt: -1 });
        res.json(transactions);
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: "server error " });
      }
    });

    app.post("/contact", async (req, res) => {
      try {
        const { name, phone, email, message } = req.body;

        if (!name || !phone || !email || !message)
          return res.status(400).json({ message: "All fields are required." });

        const newMessage = new Contact({ name, phone, email, message });
        await newMessage.save();

        res.json({ message: "Message sent successfully " });
      } catch (err) {
        console.error(err);
        res.status(500).json({ message: " server error" });
      }
    });


    app.get("/", (req, res) => {
      res.redirect("/home.html");
    });

    // ✅ مهم لـ Playwright
    app.get("/health", (req, res) => {
      res.status(200).send("ok");
    });


app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
