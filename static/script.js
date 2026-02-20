/**
 * script.js — Client-side logic for CypherCraft: The Password Guardian.
 *
 * Handles:
 *   - Live password analysis with debounced API calls
 *   - Breach checking via backend (k-anonymity passthrough)
 *   - Password generator UI controls
 *   - Copy-to-clipboard with auto-clear
 *   - Show/hide password toggles
 *
 * Security: No passwords are logged or stored client-side.
 */

// ─── API Helpers ─────────────────────────────────────────────
const API_BASE = "";

async function apiPost(endpoint, data) {
    const response = await fetch(`${API_BASE}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
    });
    if (!response.ok) throw new Error(`API error: ${response.status}`);
    return response.json();
}

// ─── Debounce Utility ────────────────────────────────────────
function debounce(fn, delay) {
    let timer;
    return (...args) => {
        clearTimeout(timer);
        timer = setTimeout(() => fn(...args), delay);
    };
}

// ─── Password Analyzer ──────────────────────────────────────
const analyzerInput = document.getElementById("analyzer-input");
const analyzerToggle = document.getElementById("analyzer-toggle");
const strengthBar = document.getElementById("strength-bar");
const strengthLabel = document.getElementById("strength-label");
const entropyValue = document.getElementById("entropy-value");
const crackTimeValue = document.getElementById("crack-time-value");
const charsetValue = document.getElementById("charset-value");
const lengthValue = document.getElementById("length-value");

// Policy elements
const policyLength = document.getElementById("policy-length");
const policyUpper = document.getElementById("policy-upper");
const policyLower = document.getElementById("policy-lower");
const policyNumber = document.getElementById("policy-number");
const policySymbol = document.getElementById("policy-symbol");

// Toggle password visibility for analyzer
analyzerToggle.addEventListener("click", () => {
    const isPassword = analyzerInput.type === "password";
    analyzerInput.type = isPassword ? "text" : "password";
    analyzerToggle.textContent = isPassword ? "🙈" : "👁️";
});

// Live analysis on keystroke (debounced)
const analyzePassword = debounce(async (password) => {
    if (!password) {
        resetAnalyzer();
        return;
    }

    try {
        const result = await apiPost("/api/analyze", { password });
        updateAnalyzerUI(result);
    } catch (err) {
        // Silently handle — don't expose errors to console
    }
}, 300);

analyzerInput.addEventListener("input", (e) => {
    analyzePassword(e.target.value);
});

function updateAnalyzerUI(result) {
    // Strength bar
    const strengthPercent = Math.min(100, (result.entropy / 100) * 100);
    strengthBar.style.width = `${strengthPercent}%`;
    strengthBar.style.backgroundColor = result.strength.color;

    // Labels
    strengthLabel.textContent = result.strength.label;
    strengthLabel.style.color = result.strength.color;
    entropyValue.textContent = `${result.entropy} bits`;
    crackTimeValue.textContent = result.crack_time;
    charsetValue.textContent = result.charset_size;
    lengthValue.textContent = result.length;

    // Policy checks
    updatePolicy(policyLength, result.policy.min_length);
    updatePolicy(policyUpper, result.policy.has_uppercase);
    updatePolicy(policyLower, result.policy.has_lowercase);
    updatePolicy(policyNumber, result.policy.has_number);
    updatePolicy(policySymbol, result.policy.has_symbol);
}

function updatePolicy(element, pass) {
    const icon = element.querySelector(".policy-icon");
    const text = element.querySelector(".policy-text");
    if (pass) {
        icon.textContent = "✅";
        element.classList.add("policy-pass");
        element.classList.remove("policy-fail");
    } else {
        icon.textContent = "⬜";
        element.classList.remove("policy-pass");
        element.classList.add("policy-fail");
    }
}

function resetAnalyzer() {
    strengthBar.style.width = "0%";
    strengthLabel.textContent = "—";
    strengthLabel.style.color = "#94a3b8";
    entropyValue.textContent = "—";
    crackTimeValue.textContent = "—";
    charsetValue.textContent = "—";
    lengthValue.textContent = "0";
    [policyLength, policyUpper, policyLower, policyNumber, policySymbol].forEach((el) => {
        el.querySelector(".policy-icon").textContent = "⬜";
        el.classList.remove("policy-pass");
        el.classList.add("policy-fail");
    });
}

// ─── Breach Checker ──────────────────────────────────────────
const breachInput = document.getElementById("breach-input");
const breachToggle = document.getElementById("breach-toggle");
const breachButton = document.getElementById("breach-button");
const breachResult = document.getElementById("breach-result");
const breachIcon = document.getElementById("breach-icon");
const breachText = document.getElementById("breach-text");
const breachLoading = document.getElementById("breach-loading");

breachToggle.addEventListener("click", () => {
    const isPassword = breachInput.type === "password";
    breachInput.type = isPassword ? "text" : "password";
    breachToggle.textContent = isPassword ? "🙈" : "👁️";
});

breachButton.addEventListener("click", async () => {
    const password = breachInput.value.trim();
    if (!password) {
        showBreachResult("⚠️", "Please enter a password to check.", "#eab308");
        return;
    }

    // Show loading state
    breachLoading.classList.remove("hidden");
    breachResult.classList.add("hidden");
    breachButton.disabled = true;

    try {
        const result = await apiPost("/api/breach-check", { password });

        if (result.error) {
            showBreachResult("⚠️", result.error, "#eab308");
        } else if (result.breached) {
            showBreachResult(
                "🚨",
                `Found in ${result.count.toLocaleString()} known breaches!`,
                "#ef4444"
            );
        } else {
            showBreachResult("✅", "No known breaches found.", "#22c55e");
        }
    } catch (err) {
        showBreachResult("⚠️", "Network error. Please try again.", "#eab308");
    } finally {
        breachLoading.classList.add("hidden");
        breachButton.disabled = false;
    }
});

function showBreachResult(icon, text, color) {
    breachResult.classList.remove("hidden");
    breachResult.classList.add("animate-slide-in");
    breachIcon.textContent = icon;
    breachText.textContent = text;
    breachText.style.color = color;
}

// ─── Password Generator ─────────────────────────────────────
const genTypeSelect = document.getElementById("gen-type");
const genLengthSlider = document.getElementById("gen-length");
const genLengthLabel = document.getElementById("gen-length-label");
const genWordCount = document.getElementById("gen-word-count");
const genResult = document.getElementById("gen-result");
const genToggle = document.getElementById("gen-toggle");
const genCopy = document.getElementById("gen-copy");
const genGenerate = document.getElementById("gen-generate");

// Standard options
const genUppercase = document.getElementById("gen-uppercase");
const genLowercase = document.getElementById("gen-lowercase");
const genNumbers = document.getElementById("gen-numbers");
const genSymbols = document.getElementById("gen-symbols");
const genExcludeAmbiguous = document.getElementById("gen-exclude-ambiguous");

// Option containers
const standardOptions = document.getElementById("standard-options");
const pinOptions = document.getElementById("pin-options");
const passphraseOptions = document.getElementById("passphrase-options");

// Switch visible options based on type
genTypeSelect.addEventListener("change", () => {
    const type = genTypeSelect.value;
    standardOptions.classList.toggle("hidden", type !== "standard");
    pinOptions.classList.toggle("hidden", type !== "pin");
    passphraseOptions.classList.toggle("hidden", type !== "passphrase");
});

// Update slider label
genLengthSlider.addEventListener("input", () => {
    genLengthLabel.textContent = genLengthSlider.value;
});

// Show/hide generated password
let genPasswordVisible = false;
genToggle.addEventListener("click", () => {
    genPasswordVisible = !genPasswordVisible;
    if (genPasswordVisible) {
        genResult.type = "text";
        genToggle.textContent = "🙈";
    } else {
        genResult.type = "password";
        genToggle.textContent = "👁️";
    }
});

// Generate password
genGenerate.addEventListener("click", generateNewPassword);

async function generateNewPassword() {
    const type = genTypeSelect.value;

    const options = { type };

    if (type === "standard") {
        options.length = parseInt(genLengthSlider.value);
        options.uppercase = genUppercase.checked;
        options.lowercase = genLowercase.checked;
        options.numbers = genNumbers.checked;
        options.symbols = genSymbols.checked;
        options.exclude_ambiguous = genExcludeAmbiguous.checked;
    } else if (type === "pin") {
        const pinLen = document.getElementById("gen-pin-length");
        options.length = parseInt(pinLen.value);
    } else if (type === "passphrase") {
        options.word_count = parseInt(genWordCount.value);
    }

    try {
        genGenerate.disabled = true;
        genGenerate.textContent = "⏳ Generating...";

        const result = await apiPost("/api/generate", options);
        genResult.value = result.password;

        // Show the password briefly
        genResult.type = "text";
        genPasswordVisible = true;
        genToggle.textContent = "🙈";
    } catch (err) {
        genResult.value = "Error generating password";
    } finally {
        genGenerate.disabled = false;
        genGenerate.textContent = "🔄 Generate";
    }
}

// Copy to clipboard
genCopy.addEventListener("click", async () => {
    const password = genResult.value;
    if (!password) return;

    try {
        await navigator.clipboard.writeText(password);
        genCopy.textContent = "✅ Copied!";
        genCopy.classList.add("copied");

        // Auto-clear clipboard after 30 seconds
        setTimeout(() => {
            navigator.clipboard.writeText("").catch(() => { });
        }, 30000);

        // Reset button after 2 seconds
        setTimeout(() => {
            genCopy.textContent = "📋 Copy";
            genCopy.classList.remove("copied");
        }, 2000);
    } catch (err) {
        // Fallback for older browsers
        genResult.type = "text";
        genResult.select();
        document.execCommand("copy");
        genCopy.textContent = "✅ Copied!";
        setTimeout(() => {
            genCopy.textContent = "📋 Copy";
        }, 2000);
    }
});

// Generate one on page load
window.addEventListener("DOMContentLoaded", generateNewPassword);
