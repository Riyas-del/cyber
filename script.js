
"use strict";

const $ = (id) => document.getElementById(id);

const pages = [
  "dashboard",
  "password",
  "inspector",
  "tips",
  "about"
];

const titles = {
  dashboard: "Your digital safety.",
  password: "Create stronger passwords.",
  inspector: "Pause before you click.",
  tips: "Build safer digital habits.",
  about: "Security without fake promises."
};

let generatedPassword = "";
let toastTimer;

function toast(message) {
  const element = $("toast");
  element.textContent = message;
  element.classList.add("show");

  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    element.classList.remove("show");
  }, 2400);
}

// Navigation
function showPage(page) {
  if (!pages.includes(page)) return;

  pages.forEach((name) => {
    $(name).classList.toggle("hidden", name !== page);
  });

  document.querySelectorAll("[data-page]").forEach((button) => {
    button.classList.toggle("active", button.dataset.page === page);
  });

  $("page-title").textContent = titles[page];
  window.scrollTo({ top: 0, behavior: "smooth" });
}

document.querySelectorAll("[data-page]").forEach((button) => {
  button.addEventListener("click", () => {
    showPage(button.dataset.page);
  });
});

document.querySelectorAll("[data-open]").forEach((button) => {
  button.addEventListener("click", () => {
    showPage(button.dataset.open);
  });
});

$("quick-generate").addEventListener("click", () => {
  showPage("password");
  generatePassword();
});

// Password generator
$("length").addEventListener("input", () => {
  $("length-value").textContent = $("length").value;
});

function randomIndex(max) {
  if (!Number.isInteger(max) || max < 1) {
    throw new Error("Invalid random range.");
  }

  // Rejection sampling avoids modulo bias.
  const range = 0x100000000;
  const limit = Math.floor(range / max) * max;
  const numbers = new Uint32Array(1);

  do {
    crypto.getRandomValues(numbers);
  } while (numbers[0] >= limit);

  return numbers[0] % max;
}

function generatePassword() {
  if (!window.crypto?.getRandomValues) {
    toast("Secure random generation is unavailable.");
    return;
  }

  const sets = [];

  if ($("lower").checked) {
    sets.push("abcdefghijklmnopqrstuvwxyz");
  }

  if ($("upper").checked) {
    sets.push("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
  }

  if ($("numbers").checked) {
    sets.push("0123456789");
  }

  if ($("symbols").checked) {
    sets.push("!@#$%^&*()-_=+[]{}:,.?");
  }

  if (sets.length === 0) {
    toast("Select at least one character set.");
    return;
  }

  const length = Number($("length").value);
  const allCharacters = sets.join("");
  const characters = [];

  // Ensure every selected character set is represented.
  sets.forEach((set) => {
    characters.push(set[randomIndex(set.length)]);
  });

  while (characters.length < length) {
    characters.push(
      allCharacters[randomIndex(allCharacters.length)]
    );
  }

  // Cryptographically random Fisher-Yates shuffle.
  for (let i = characters.length - 1; i > 0; i--) {
    const j = randomIndex(i + 1);
    [characters[i], characters[j]] =
      [characters[j], characters[i]];
  }

  generatedPassword = characters.slice(0, length).join("");
  $("password-output").value = generatedPassword;

  const entropy = Math.floor(
    length * Math.log2(allCharacters.length)
  );

  $("password-status").textContent =
    `Generated locally. Estimated search space: ${entropy} bits. ` +
    "Use a unique password for every account.";

  toast("New password generated.");
}

$("generate").addEventListener("click", generatePassword);

// Copy generated password
$("copy-password").addEventListener("click", async () => {
  if (!generatedPassword) {
    toast("Generate a password first.");
    return;
  }

  try {
    await navigator.clipboard.writeText(generatedPassword);
    toast("Password copied.");
  } catch {
    // Fallback for browsers with limited clipboard support.
    const field = $("password-output");
    field.focus();
    field.select();

    try {
      const success = document.execCommand("copy");
      toast(success ? "Password copied." : "Copy was blocked.");
    } catch {
      toast("Copy blocked. Select and copy the password manually.");
    }

    field.setSelectionRange(0, 0);
  }
});

// Escape untrusted strings before placing them in HTML.
function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[character]);
}

// URL pattern inspector. This is not a threat-intelligence scan.
function inspectURL(input) {
  let candidate = input.trim();

  if (!candidate) {
    return { error: "Enter a website URL." };
  }

  if (!/^[a-zA-Z][a-zA-Z\d+.-]*:/.test(candidate)) {
    candidate = "https://" + candidate;
  }

  let url;

  try {
    url = new URL(candidate);
  } catch {
    return {
      error: "Invalid URL. Check the address and try again."
    };
  }

  const findings = [];
  const hostname = url.hostname.toLowerCase();

  function flag(level, title, detail) {
    findings.push({ level, title, detail });
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    flag(
      "bad",
      "Unexpected protocol",
      `The address uses ${url.protocol}, not a standard web protocol.`
    );
  }

  if (url.protocol === "http:") {
    flag(
      "warn",
      "HTTPS is not enabled",
      "HTTP does not provide HTTPS transport encryption."
    );
  }

  if (url.username || url.password) {
    flag(
      "bad",
      "Credentials in URL",
      "The address contains embedded username or password fields."
    );
  }

  if (hostname.split(".").some(part => part.startsWith("xn--"))) {
    flag(
      "warn",
      "Internationalized hostname",
      "Check carefully for lookalike characters in the domain."
    );
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    flag(
      "warn",
      "Numeric hostname",
      "The address uses an IPv4-style hostname. Verify the source."
    );
  }

  if (hostname.split(".").length >= 5) {
    flag(
      "warn",
      "Many subdomain levels",
      "Read the hostname carefully to identify the actual domain."
    );
  }

  if (hostname.length > 50) {
    flag(
      "warn",
      "Long hostname",
      "Long hostnames can make deceptive domains harder to notice."
    );
  }

  if (url.port && !["80", "443"].includes(url.port)) {
    flag(
      "warn",
      "Nonstandard port",
      `The address specifies port ${url.port}. Verify why it is needed.`
    );
  }

  if (/(login|verify|account|password|wallet|payment)/i.test(hostname)) {
    flag(
      "warn",
      "Account-related wording",
      "Account-related words occur in the hostname. This alone does not prove fraud."
    );
  }

  if ((url.search + url.hash).length > 150) {
    flag(
      "warn",
      "Long URL parameters",
      "The URL may contain sensitive tokens. Avoid sharing it publicly."
    );
  }

  if (findings.length === 0) {
    flag(
      "good",
      "No obvious pattern flags",
      "This limited check found no configured warning patterns. The site is not verified as safe."
    );
  }

  return { url, findings };
}

$("url-form").addEventListener("submit", (event) => {
  event.preventDefault();

  const resultElement = $("url-result");
  const result = inspectURL($("url-input").value);

  resultElement.classList.remove("hidden");

  if (result.error) {
    resultElement.className = "result";
    resultElement.innerHTML =
      `<strong>Unable to inspect URL</strong><p>${escapeHTML(result.error)}</p>`;
    return;
  }

  const hasBad = result.findings.some(f => f.level === "bad");
  const hasWarning = result.findings.some(f => f.level === "warn");

  resultElement.className = "result";

  if (hasBad) {
    resultElement.style.borderColor = "#ff9ca8";
  } else if (hasWarning) {
    resultElement.style.borderColor = "#ffd38a";
  } else {
    resultElement.style.borderColor = "#87f0c0";
  }

  const heading = hasBad
    ? "Warning signs found"
    : hasWarning
      ? "Review this URL carefully"
      : "No obvious pattern flags";

  resultElement.innerHTML = `
    <h3>${heading}</h3>
    <p><strong>Hostname:</strong> ${escapeHTML(result.url.hostname)}</p>
    <p><strong>Protocol:</strong> ${escapeHTML(result.url.protocol)}</p>
    <div class="findings">
      ${result.findings.map(f => `
        <article class="tip">
          <strong>${escapeHTML(f.title)}</strong>
          <p>${escapeHTML(f.detail)}</p>
        </article>
      `).join("")}
    </div>
    <p class="notice">
      This is a local heuristic, not a live security scan.
      No reputation database was queried. Never treat a clean
      result as proof that a website is safe.
    </p>
  `;
});

// Clear URL inspector
$("clear-url").addEventListener("click", () => {
  $("url-input").value = "";
  $("url-result").classList.add("hidden");
  $("url-result").replaceChildren();
  $("url-input").focus();
});

// Reset page state
$("reset-app").addEventListener("click", () => {
  generatedPassword = "";
  $("password-output").value = "";
  $("password-status").textContent =
    "Choose your options and generate a password.";

  $("url-input").value = "";
  $("url-result").classList.add("hidden");
  $("url-result").replaceChildren();

  $("length").value = 20;
  $("length-value").textContent = "20";

  $("lower").checked = true;
  $("upper").checked = true;
  $("numbers").checked = true;
  $("symbols").checked = true;

  showPage("dashboard");
  toast("Page state reset.");
});
  
