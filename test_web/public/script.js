async function signup() {
  const username = document.getElementById("signup-username").value;
  const password = document.getElementById("signup-password").value;

  const res = await fetch("/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  const data = await res.json();
  document.getElementById("message").innerText = data.message;

  if (data.message === "Signup successful") {
    setTimeout(() => {
      window.location.href = "login.html";
    }, 1000);
  }
}

async function login() {
  const username = document.getElementById("login-username").value;
  const password = document.getElementById("login-password").value;

  const res = await fetch("/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  const data = await res.json();
  document.getElementById("message").innerText = data.message;

  if (data.message === "Login successful") {
    setTimeout(() => {
      window.location.href = "home.html";
    }, 1000);
  }
}
