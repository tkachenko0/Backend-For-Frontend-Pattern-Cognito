const API_URL = "http://localhost:3000";

async function checkAuth() {
  try {
    const res = await fetch(`${API_URL}/profile`, {
      credentials: "include",
    });
    if (res.ok) {
      const data = await res.json();
      showAuthenticated(data.username);
    } else {
      showUnauthenticated();
    }
  } catch (e) {
    showUnauthenticated();
  }
}

function showAuthenticated(username) {
  document.getElementById("loading").style.display = "none";
  document.getElementById("authenticated").style.display = "block";
  document.getElementById("username").textContent = username;
}

async function fetchProtected() {
  try {
    const res = await fetch(`${API_URL}/protected`, {
      credentials: "include",
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({ error: res.statusText }));
      alert(`Error ${res.status}: ${data.error || res.statusText}`);
      return;
    }
    const data = await res.json();
    document.getElementById("protected-data").textContent = JSON.stringify(
      data,
      null,
      2,
    );
  } catch (e) {
    alert(`Failed to load protected data: ${e.message}`);
  }
}

function showUnauthenticated() {
  document.getElementById("loading").style.display = "none";
  document.getElementById("unauthenticated").style.display = "block";
}

function login() {
  window.location.href = `${API_URL}/login`;
}

async function logout() {
  try {
    await fetch(`${API_URL}/logout`, { method: "PUT", credentials: "include" });
    window.location.reload();
  } catch (e) {
    alert(`Logout failed: ${e.message}`);
  }
}

async function incrementCounter() {
  try {
    const res = await fetch(`${API_URL}/counter/increment`, {
      method: "POST",
      credentials: "include",
    });
    const data = await res.json();
    document.getElementById("counter-data").textContent = JSON.stringify(
      data,
      null,
      2,
    );
  } catch (e) {
    alert(`Failed: ${e.message}`);
  }
}

async function checkCounter() {
  try {
    const res = await fetch(`${API_URL}/counter`, {
      credentials: "include",
    });
    const data = await res.json();
    document.getElementById("counter-data").textContent = JSON.stringify(
      data,
      null,
      2,
    );
  } catch (e) {
    alert(`Failed: ${e.message}`);
  }
}

checkAuth();
