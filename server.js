// server.js
import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import Transaction from "./models/Transaction.js";

const JWT_SECRET = "secret_key_must_change_in_prod";
const JWT_EXPIRES = "6h";
const SALT_ROUNDS = 10;

const app = express();
const PORT = 3000;

// Middlewares
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json());

// Connect to MongoDB
mongoose.connect("mongodb://127.0.0.1:27017/onlineBankingDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log("conncted to MongoDB succfully."))
  .catch((err) => console.error("error to connect to data base ", err));

// Schema
const userSchema = new mongoose.Schema({
firstName: { type: String, required: true },
lastName: { type: String, required: true },
nationalId: { type: String, required: true },
username: { type: String, required: true, unique: true },
email: { type: String, required: true, unique: true },
phone: { type: String, required: true },
password: { type: String, required: true },
dob: { type: Date, required: true },
balance: { type: Number, default: 10000 },
}, { timestamps: true });


const User = mongoose.model("User", userSchema);
const cardSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },

  cardName: {
    type: String,
    required: true
  },

accountNumber: {
  type: String,
  required: true,
  validate: {
    validator: function(v) {
      return /^[0-9]{16}$/.test(v);
    },
    message: "Card number must be exactly 16 digits"
  }
},


  cardType: {
    type: String,
    enum: ["debit", "credit"],
    required: true
  },

  expiryDate: {
    type: String,
    required: true
  },

  cvv: {
    type: String,
    required: true
  },

   cardPassword: {          // ✅ الإضافة دي بس
    type: String,
    required: true
  }
  
}, { timestamps: true });
const Card = mongoose.model("Card", cardSchema);
const contactSchema = new mongoose.Schema({
  name: { type: String, required: true },
  phone: { type: String, required: true },
  email: { type: String, required: true },
  message: { type: String, required: true }
}, { timestamps: true });

const Contact = mongoose.model("Contact", contactSchema);

// Helpers
function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

function validateMobile(mobile) {
  // بسيط: يقبل أرقام فقط وبداية 7-15 رقم
  const re = /^[0-9]{7,15}$/;
  return re.test(mobile);
}

// Register endpoint
app.post("/register", async (req, res) => {
  console.log("📥 البيانات المستلمة:", req.body);

  try {
    const {
      firstName,
      lastName,
      nationalId,
      username,
      email,
      phone,
      password,
      dob
    } = req.body;

    if (
      !firstName || !lastName || !nationalId ||
      !username || !email || !phone || !password || !dob
    ) {
      return res.status(400).json({ message: "جميع الحقول مطلوبة" });
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ message: "صيغة البريد الالكتروني غير صحيحة" });
    }

    if (!validateMobile(phone)) {
      return res.status(400).json({ message: "رقم الموبايل غير صالح" });
    }

    const existUser = await User.findOne({
      $or: [{ username }, { email }]
    });

    if (existUser) {
      return res.status(409).json({ message: "اسم المستخدم أو البريد مستخدم بالفعل" });
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
  message: "تم التسجيل بنجاح",
  user: userSafe
});

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "خطأ في السيرفر" });
  }
}); // ✅ القفلة الصح هنا




// -------- Login --------
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    // 1️⃣ تحقق من الحقول
    if (!username || !password) {
      return res.status(400).json({ message: "جميع الحقول مطلوبة" });
    }

    // 2️⃣ دور على المستخدم بالـ username
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: "اسم المستخدم أو كلمة المرور غير صحيحة" });
    }

    // 3️⃣ قارن الباسورد
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ message: "اسم المستخدم أو كلمة المرور غير صحيحة" });
    }

    // 4️⃣ إنشاء JWT
    const token = jwt.sign(
      { userId: user._id },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    // 5️⃣ رجّع بيانات آمنة
    const { password: _p, __v, ...userSafe } = user.toObject();

    return res.json({
      message: "تم تسجيل الدخول بنجاح",
      token,
      user: userSafe
    });

  } catch (err) {
    return res.status(500).json({
      message: "حدث خطأ في السيرفر",
      error: err.message
    });
  }
});



app.get("/user/:id", async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select("-password -__v");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});




app.put("/user/:id", async (req, res) => {
  try {
    const updatedUser = await User.findByIdAndUpdate(
      req.params.id,
      req.body,
{ new: true, runValidators: true }
    );

    const { password, __v, ...safeUser } = updatedUser.toObject();
    res.json({ user: safeUser });

  } catch (err) {
    res.status(500).json({ message: "خطأ في التحديث" });
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
    if (!card) {
      return res.status(404).json({ message: "لا يوجد كارت" });
    }

    const match = await bcrypt.compare(password, card.cardPassword);
    if (!match) {
      return res.status(400).json({ message: "باسورد الكارت غلط" });
    }

    res.json({ message: "ok" });
  } catch (err) {
    res.status(500).json({ message: "خطأ في السيرفر" });
  }
});

app.post("/transfer/bank-transfer", async (req, res) => {
  const { userId, bank, beneficiaryName, beneficiaryAccount, amount } = req.body;

  if (!userId || !beneficiaryAccount || !amount) {
    return res.status(400).json({ message: "بيانات ناقصة" });
  }

  try {
    // 1️⃣ جلب كارت المرسل
    const senderCard = await Card.findOne({ userId });
    if (!senderCard) {
      return res.status(404).json({ message: "كارت المرسل غير موجود" });
    }

    // 2️⃣ جلب المستخدم المرسل
    const sender = await User.findById(userId);
    if (!sender) {
      return res.status(404).json({ message: "المرسل غير موجود" });
    }

    const transferAmount = Number(amount);
    if (sender.balance < transferAmount) {
      return res.status(400).json({ message: "الرصيد غير كافي" });
    }

    // 3️⃣ جلب كارت المستفيد عن طريق رقم الحساب
    const receiverCard = await Card.findOne({
      accountNumber: beneficiaryAccount
    });

    if (!receiverCard) {
      return res.status(404).json({ message: "رقم الحساب غير صحيح" });
    }

    // ❌ منع التحويل لنفس الحساب
    if (receiverCard.userId.toString() === userId) {
      return res.status(400).json({ message: "لا يمكن التحويل لنفس الحساب" });
    }

    // 4️⃣ جلب المستخدم المستفيد
    const receiver = await User.findById(receiverCard.userId);
    if (!receiver) {
      return res.status(404).json({ message: "المستفيد غير موجود" });
    }

    // 5️⃣ تنفيذ التحويل
    sender.balance -= transferAmount;
    receiver.balance += transferAmount;

    await sender.save();
    await receiver.save();

    // 6️⃣ تسجيل العملية عند المرسل
    await Transaction.create({
      userId: sender._id,
      type: "bank",
      amount: transferAmount,
      source: "Bank",
      direction: "out",
      beneficiaryName,
      beneficiaryAccount
    });

    // 7️⃣ تسجيل العملية عند المستفيد
    await Transaction.create({
      userId: receiver._id,
      type: "bank",
      amount: transferAmount,
      source: "Bank",
      direction: "in",
      senderName: sender.firstName + " " + sender.lastName,
      senderAccount: senderCard.accountNumber
    });

    // 8️⃣ الرد
    res.json({
      message: "تم التحويل بنجاح",
      newBalance: sender.balance
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "خطأ في السيرفر" });
  }
});


// Wallet Transfer (one side only)
app.post("/transfer/wallet-transfer", async (req, res) => {
  const { userId, walletNumber, amount } = req.body;

  if (!userId || !walletNumber || !amount) {
    return res.status(400).json({ message: "بيانات ناقصة" });
  }

  try {
    // 1️⃣ هات المستخدم
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "المستخدم غير موجود" });
    }

    // 2️⃣ تحقق من الرصيد
    if (user.balance < amount) {
      return res.status(400).json({ message: "الرصيد غير كافي" });
    }

    // 3️⃣ خصم الرصيد
    user.balance -= Number(amount);
    await user.save();

    // 4️⃣ تسجيل العملية (طرف واحد بس)
    await Transaction.create({
      userId: user._id,
      type: "wallet",
      amount,
      source: "Wallet",
      direction: "out",
      beneficiaryName: "Wallet Transfer",
      beneficiaryAccount: walletNumber
    });

    // 5️⃣ رجّع الرصيد الجديد
    res.json({
      message: "تم التحويل للمحفظة بنجاح",
      newBalance: user.balance
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "خطأ في السيرفر" });
  }
});



// Add Card
app.post("/add-card", async (req, res) => {
  try {
    const {
      userId,
      cardName,
      accountNumber,
      cardType,
      expiryDate,
      cvv,
      cardPassword
    } = req.body;

    // 1️⃣ Check required fields
    if (
      !userId || !cardName || !accountNumber ||
      !cardType || !expiryDate || !cvv || !cardPassword
    ) {
      return res.status(400).json({ message: "all fields are required" });
    }

    // 2️⃣ Validate card number (must be exactly 16 digits)
    if (!/^[0-9]{16}$/.test(accountNumber)) {
      return res.status(400).json({
        message: "Card number must be exactly 16 digits"
      });
    }

    // 3️⃣ Hash card password
    const hashedCardPassword = await bcrypt.hash(cardPassword, SALT_ROUNDS);

    const newCard = new Card({
      userId,
      cardName,
      accountNumber,
      cardType,
      expiryDate,
      cvv,
      cardPassword: hashedCardPassword
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

    if (!card) {
      return res.status(404).json({ message: "no user for this card" });
    }

    // رجّع بيانات آمنة (من غير cvv ولا password)
    const { cvv, cardPassword, __v, ...cardSafe } = card.toObject();

    res.json({ card: cardSafe });

  } catch (err) {
    res.status(500).json({
      message: "server error",
      error: err.message
    });
  }
});
app.post("/atm/transaction", async (req, res) => {
  try {
    const { cardNumber, cardPassword, amount, type } = req.body;

    if (!cardNumber || !cardPassword || !amount || !type) {
      return res.status(400).json({ message: "بيانات ناقصة" });
    }

    // 1️⃣ البحث عن الكارت عن طريق رقم الحساب
    const cleanCardNumber = cardNumber.replace(/\s|-/g, "");
const card = await Card.findOne({ accountNumber: cleanCardNumber });

    if (!card) {
      return res.status(404).json({ message: "الكارت غير موجود" });
    }

    // 2️⃣ التحقق من PIN
    const match = await bcrypt.compare(cardPassword, card.cardPassword);
    if (!match) {
      return res.status(401).json({ message: "Invalid PIN." });
    }

    // 3️⃣ جلب المستخدم
    const user = await User.findById(card.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // 4️⃣ تنفيذ العملية
    if (type === "withdrawal") {
      if (user.balance < amount) {
        return res.status(400).json({ message:"Insufficient balance" });
      }
      user.balance -= Number(amount);
    }

    if (type === "deposit") {
      user.balance += Number(amount);
    }

    await user.save();

    // 5️⃣ تسجيل العملية
 await Transaction.create({
  userId: user._id,
  type,
  amount,
  source: "ATM"
});



    res.json({
      message: "operation was completed successfully",
      newBalance: user.balance
    });
 
  
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "server error" });
  }
});
app.get("/transactions/:userId", async (req, res) => {
  try {
    const { userId } = req.params;

    const transactions = await Transaction.find({ userId })
      .sort({ createdAt: -1 });

    res.json(transactions);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "server error " });
  }
});
app.post("/contact", async (req, res) => {
  try {
    const { name, phone, email, message } = req.body;

    if (!name || !phone || !email || !message) {
      return res.status(400).json({ message: "All fields are required." });
    }

    const newMessage = new Contact({
      name,
      phone,
      email,
      message
    });

    await newMessage.save();

res.json({ message: "Message sent successfully ✅" });


  } catch (err) {
    console.error(err);
    res.status(500).json({ message: " server error" });
  }
});

app.use(express.static("public"));

app.get("/", (req, res) => {
  res.send({ status: "ok", message: "Server is running" });
});

app.listen(PORT, () => {
  console.log(`server running in  http://localhost:${PORT}`);
});
