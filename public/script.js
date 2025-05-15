document.addEventListener("DOMContentLoaded", () => {
  // Redirect handlers
  const registerBtn = document.getElementById("register-button");
  if (registerBtn) {
    registerBtn.addEventListener("click", () => {
      window.location.href = "/register";
    });
  }

  const loginBtn = document.getElementById("login-button");
  if (loginBtn) {
    loginBtn.addEventListener("click", () => {
      window.location.href = "/login";
    });
  }

  // Toggle lesson form visibility
  const btn = document.querySelector(".btn-open");
  const form = document.querySelector(".lesson-form");
  if (btn && form) {
    btn.addEventListener("click", function () {
      if (form.classList.contains("hidden")) {
        form.classList.remove("hidden");
        btn.textContent = "Close";
      } else {
        form.classList.add("hidden");
        btn.textContent = "Share New Lesson";
      }
    });
  }
});

document.getElementById("register-button")?.addEventListener("click", () => {
  window.location.href = "/register";
});

document.getElementById("login-button")?.addEventListener("click", () => {
  window.location.href = "/login";
});
