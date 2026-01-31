const API_URL = "http://localhost:8080";
let profileData = null;

async function checkAuth() {
  try {
    const res = await fetch(`${API_URL}/auth/status`, {
      credentials: "include",
    });
    if (res.ok) {
      const data = await res.json();
      if (data.authenticated) {
        await loadProfile();
      } else {
        showUnauthenticated();
      }
    } else {
      showUnauthenticated();
    }
  } catch (e) {
    showUnauthenticated();
  }
}

async function loadProfile() {
  try {
    const res = await fetch(`${API_URL}/api/user`, {
      credentials: "include",
    });
    if (res.ok) {
      const data = await res.json();
      profileData = data;
      showAuthenticated(data.user.name || data.user.email);
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
  document.getElementById("unauthenticated").style.display = "none";
  document.getElementById("username").textContent = username;

  if (profileData) {
    document.getElementById("profile-data").textContent = JSON.stringify(
      profileData,
      null,
      2,
    );
  }
}

async function fetchProtected() {
  try {
    const res = await fetch(`${API_URL}/api/protected`, {
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
  window.location.href = `${API_URL}/auth/login`;
}

function testReturnTo(path) {
  window.location.href = `${API_URL}/auth/login?returnTo=${encodeURIComponent(path)}`;
}

async function logout() {
  window.location.href = `${API_URL}/auth/logout`;
}

async function incrementCounter() {
  try {
    const res = await fetch(`${API_URL}/api/counter/increment`, {
      method: "POST",
      credentials: "include",
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({ error: res.statusText }));
      alert(`Error ${res.status}: ${data.error || res.statusText}`);
      return;
    }
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
    const res = await fetch(`${API_URL}/api/counter`, {
      credentials: "include",
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({ error: res.statusText }));
      alert(`Error ${res.status}: ${data.error || res.statusText}`);
      return;
    }
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

function updateCurrentPath() {
  document.getElementById("path-value").textContent = window.location.pathname;
}

async function fetchUserInfo() {
  try {
    const res = await fetch(`${API_URL}/auth/userinfo`, {
      credentials: "include",
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({ error: res.statusText }));
      alert(`Error ${res.status}: ${data.error || res.statusText}`);
      return;
    }
    const data = await res.json();
    document.getElementById("userinfo-data").textContent = JSON.stringify(
      data,
      null,
      2,
    );
  } catch (e) {
    alert(`Failed to fetch user info: ${e.message}`);
  }
}

async function fetchDiscovery() {
  try {
    const res = await fetch(`${API_URL}/.well-known/openid-configuration`);
    if (!res.ok) {
      const data = await res.json().catch(() => ({ error: res.statusText }));
      alert(`Error ${res.status}: ${data.error || res.statusText}`);
      return;
    }
    const data = await res.json();
    document.getElementById("discovery-data").textContent = JSON.stringify(
      data,
      null,
      2,
    );
  } catch (e) {
    alert(`Failed to fetch discovery: ${e.message}`);
  }
}

async function fetchJwks() {
  try {
    const res = await fetch(`${API_URL}/.well-known/jwks.json`);
    if (!res.ok) {
      const data = await res.json().catch(() => ({ error: res.statusText }));
      alert(`Error ${res.status}: ${data.error || res.statusText}`);
      return;
    }
    const data = await res.json();
    document.getElementById("jwks-data").textContent = JSON.stringify(
      data,
      null,
      2,
    );
  } catch (e) {
    alert(`Failed to fetch JWKS: ${e.message}`);
  }
}

checkAuth();
updateCurrentPath();
