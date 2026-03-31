const errorBox = document.getElementById("errorBox");




/* ===== Steps Logic ===== */
const steps = document.querySelectorAll(".step");
let currentStep = 0;

steps.forEach((step, i) => {
  step.style.display = i === 0 ? "block" : "none";
});

function showStep(index) {
  steps.forEach((step, i) => {
    step.style.display = i === index ? "block" : "none";
  });
}

/* ===== Next ===== */
document.querySelectorAll(".nextBtn").forEach((btn) => {
  btn.addEventListener("click", () => {

    const inputs = steps[currentStep].querySelectorAll("input");
    let valid = true;

    // 1️⃣ تحقق إن الحقول مش فاضية
    inputs.forEach(input => {
      if (!input.value.trim()) valid = false;
    });

    if (!valid) {
      showError("please fill in all blanks");
      return;
    }

    // 2️⃣ تحقق National ID (Step 2)
    if (currentStep === 1) {
      const nationalId = document.getElementById("nationalId").value;

      if (!/^\d{14}$/.test(nationalId)) {
        showError("ID must be 14 digits");
        return;
      }
    }

    // 3️⃣ تحقق الباسورد (Step 4)
    if (currentStep === 3) {
      const password = document.getElementById("password").value;
      const confirmPassword = document.getElementById("confirmPassword").value;

      if (password !== confirmPassword) {
        showError("password does not match");
        return;
      }
    }

    // 4️⃣ لو كله تمام نروح للخطوة اللي بعدها
    if (currentStep < steps.length - 1) {
      currentStep++;
      showStep(currentStep);
      clearError();
    }

  });
});

/* ===== Back ===== */
document.querySelectorAll(".backBtn").forEach((btn) => {
  btn.addEventListener("click", () => {
    if (currentStep > 0) {
      currentStep--;
      showStep(currentStep);
      clearError();
    }
  });
});
function showMessage(text, type) {
  const messageDiv = document.getElementById("registerMessage");

  messageDiv.textContent = text;
  messageDiv.classList.remove("success", "error");
  messageDiv.classList.add(type);
  messageDiv.style.display = "block";

  // تختفي تلقائي بس لو خطأ
  if (type === "error") {
    setTimeout(() => {
      messageDiv.style.display = "none";
    }, 8000);
  }
}


function showError(text) {
  showMessage(text, "error");
}

function showSuccess(text) {
  showMessage(text, "success");
}

function clearError() {
  const messageDiv = document.getElementById("registerMessage");
  if (messageDiv.classList.contains("error")) {
    messageDiv.style.display = "none";
  }
}

/* ===== Submit Form ===== */
document.getElementById("registerForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  clearError();

  const firstName = document.getElementById("firstname").value.trim();
  const lastName  = document.getElementById("lastname").value.trim();
  const username  = document.getElementById("username").value.trim();
  const nationalId = document.getElementById("nationalId").value.trim();
  const email = document.getElementById("email").value.trim();
  const phone = document.getElementById("phonenumber").value.trim();
  const password = document.getElementById("password").value;
  const confirmPassword = document.getElementById("confirmPassword").value;
  const dob = document.getElementById("dob").value;

  /* ===== Validations ===== */
  if (password !== confirmPassword) {
    showError("password does not match");
    // 🔐 Password strength
if (!/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/.test(password)) {
  showError("Password must be at least 8 characters and include uppercase, lowercase, number, and symbol");
  return;
}
    return;
  }
// 📧 Email validation
if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
  showError("Invalid email format");
  return;
}
// 📱 Phone validation (Egypt)
if (!/^01[0-9]{9}$/.test(phone)) {
  showError("Invalid Egyptian phone number (must be 11 digits and start with 01)");
  return;
}
// 🎂 Age validation (21+)
const birthDate = new Date(dob);
const today = new Date();

let age = today.getFullYear() - birthDate.getFullYear();
const monthDiff = today.getMonth() - birthDate.getMonth();

if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
  age--;
}

if (age < 21) {
  showError("You must be at least 21 years old");
  return;
}

  const payload = {
    firstName,
    lastName,
    username,
    nationalId,
    email,
    phone,
    password,
    dob
  };

  console.log("Register Payload:", payload);

try {

  const res = await fetch(`/register`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });
let data;

try {
  data = await res.json();
} catch {
  showError("Invalid server response");
  return;
}  if (!res.ok) {
    showError(data.message || "error creating account");
    return;
  }


   const userData = {
  _id: data.user._id,
  firstName: data.user.firstName,
  lastName: data.user.lastName,
  username: data.user.username,
  email: data.user.email,
  phone: data.user.phone,
  nationalId: data.user.nationalId,
  dob: data.user.dob,        // ✅ السطر المهم
  balance: data.user.balance ?? 0
};

localStorage.setItem("currentUser", JSON.stringify(userData));
showSuccess(" Account created successfully");

setTimeout(() => {

  document.querySelector('button[type="submit"]').style.display = "none";

  document.querySelectorAll(".step").forEach(step => {
    step.style.display = "none";
  });

  document.querySelector(".checkbox").style.display = "none";
  document.querySelector(".login").style.display = "none";

  document.getElementById("addCardBtn").style.display = "block";
  document.getElementById("skipCardBtn").style.display = "block";

}, 800); // تأخير بسيط



  } catch (err) {
    console.error(err);
    showError("server error");
  }
});

document.getElementById("addCardBtn").addEventListener("click", () => {
  window.location.href = "add_card.html";
});

document.getElementById("skipCardBtn").addEventListener("click", () => {
  window.location.href = "dashboard.html";
});





