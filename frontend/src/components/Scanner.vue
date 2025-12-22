<template>
  <div class="scanner-container">
    <!-- Header Section -->
    <div class="header">
      <h1>Phishing Link Scanner</h1>
      <p>Check if a URL is safe before clicking</p>
    </div>

    <!-- Input Section -->
    <div class="input-section">
      <input
        v-model="url"
        type="url"
        placeholder="Enter URL (e.g., https://example.com)"
        @keyup.enter="scanUrl"
        :disabled="loading"
        class="url-input"
      />
      <button
        @click="scanUrl"
        :disabled="loading || !isValidUrl"
        :class="{ loading: loading }"
        class="scan-button"
      >
        {{ loading ? "Scanning..." : "Scan URL" }}
      </button>
    </div>

    <!-- Loading Spinner -->
    <div v-if="loading" class="loading-spinner">
      <div class="spinner"></div>
      <p>Analyzing URL security...</p>
    </div>

    <!-- Error Message -->
    <div v-if="error" class="error-message">
      <span class="error-icon">!</span>
      <p>{{ error }}</p>
    </div>

    <!-- Results Section -->
    <div v-if="result" class="results-section">
      <!-- Risk Score Badge -->
      <div class="risk-badge" :class="riskClass">
        <div class="risk-score">{{ result.risk_score }}</div>
        <div class="risk-label">{{ riskLabel }}</div>
      </div>

      <!-- URL Display -->
      <div class="url-display">
        <strong>Scanned URL:</strong>
        <a :href="result.url" target="_blank" rel="noopener noreferrer">
          {{ result.url }}
        </a>
      </div>

      <!-- Detection Details -->
      <div class="detection-details">
        <h3>Detection Summary</h3>
        <div class="detection-grid">
          <div class="detection-item malicious">
            <span class="count">{{ result.detections.malicious }}</span>
            <span class="label">Malicious</span>
          </div>
          <div class="detection-item suspicious">
            <span class="count">{{ result.detections.suspicious }}</span>
            <span class="label">Suspicious</span>
          </div>
          <div class="detection-item clean">
            <span class="count">{{ result.detections.undetected }}</span>
            <span class="label">Clean</span>
          </div>
          <div class="detection-item total">
            <span class="count">{{ result.detections.total_engines }}</span>
            <span class="label">Total Engines</span>
          </div>
        </div>
      </div>

      <!-- Infrastructure Information -->
      <div
        v-if="result.infrastructure && !result.infrastructure.error"
        class="infrastructure-info"
      >
        <h3>Domain Information</h3>
        <div class="info-grid">
          <div class="info-item">
            <span class="info-label">Domain:</span>
            <span class="info-value">{{ result.infrastructure.domain }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">Creation Date:</span>
            <span class="info-value">{{
              result.infrastructure.creation_date
            }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">Registrar:</span>
            <span class="info-value">{{
              result.infrastructure.registrar
            }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">IP Address:</span>
            <span class="info-value">{{
              result.infrastructure.ip_address
            }}</span>
          </div>
        </div>
      </div>

      <!-- Categories -->
      <div
        v-if="result.categories && result.categories.length > 0"
        class="categories"
      >
        <h3>Threat Categories</h3>
        <div class="category-tags">
          <span
            v-for="(category, index) in result.categories"
            :key="index"
            class="category-tag"
          >
            {{ category }}
          </span>
        </div>
      </div>

      <!-- Metadata -->
      <div class="metadata">
        <p><strong>Scanned:</strong> {{ formatDate(result.scanned_at) }}</p>
        <p v-if="result.cached">
          <span class="cached-badge">Cached Result</span>
        </p>
        <p v-if="result.original_vt_score !== undefined">
          <span class="info-badge">VirusTotal: {{ result.original_vt_score }}</span>
          <span v-if="result.threat_intelligence && result.threat_intelligence.threat_score" class="info-badge">
            Threat Intel: {{ result.threat_intelligence.threat_score }}
          </span>
        </p>
      </div>

      <!-- Threat Intelligence Indicators -->
      <div
        v-if="result.threat_intelligence && result.threat_intelligence.indicators && result.threat_intelligence.indicators.length > 0"
        class="threat-indicators"
      >
        <h3>Threat Indicators Detected</h3>
        <div class="indicators-list">
          <div
            v-for="(indicator, index) in result.threat_intelligence.indicators"
            :key="index"
            class="indicator-item"
            :class="'severity-' + indicator.severity"
          >
            <span class="indicator-icon">
              {{ getSeverityIcon(indicator.severity) }}
            </span>
            <div class="indicator-content">
              <span class="indicator-message">{{ indicator.message }}</span>
              <span class="indicator-risk">+{{ indicator.risk_increase }} risk</span>
            </div>
          </div>
        </div>
        <div v-if="result.threat_intelligence.recommendation" class="threat-recommendation">
          <strong>Analysis:</strong> {{ result.threat_intelligence.recommendation }}
        </div>
      </div>

      <!-- Recommendation -->
      <div class="recommendation" :class="riskClass">
        <p>{{ recommendation }}</p>
      </div>

      <!-- Visual Sandbox -->
      <div class="visual-sandbox">
        <h3>Visual Sandbox</h3>
        <p class="sandbox-description">
          Preview the website without visiting it (using
          {{ browserDisplayName }})
        </p>

        <button
          @click="captureScreenshots"
          :disabled="screenshotLoading"
          class="capture-button"
        >
          {{ screenshotLoading ? "Capturing..." : "Capture Screenshot" }}
        </button>

        <!-- Screenshot Loading -->
        <div v-if="screenshotLoading" class="screenshot-loading">
          <div class="spinner"></div>
          <p>Capturing screenshot with {{ browserDisplayName }}...</p>
        </div>

        <!-- Screenshot Error -->
        <div v-if="screenshotError" class="error-message">
          <span class="error-icon">!</span>
          <p>{{ screenshotError }}</p>
        </div>

        <!-- Screenshots Display -->
        <div v-if="screenshots" class="screenshot-container">
          <div class="screenshot-item">
            <div class="screenshot-header">
              <span class="browser-name">{{ browserDisplayName }}</span>
              <span v-if="screenshots.success" class="status-badge success">
                Success
              </span>
              <span v-else class="status-badge failed">Failed</span>
            </div>
            <div
              v-if="screenshots.success"
              class="screenshot-preview"
              @click="openModal(screenshots.screenshot, currentBrowser)"
            >
              <img
                :src="'data:image/png;base64,' + screenshots.screenshot"
                :alt="browserDisplayName + ' Screenshot'"
              />
              <div class="preview-overlay">
                <span>Click to enlarge</span>
              </div>
            </div>
            <div v-else class="screenshot-error">
              <p>{{ screenshots.error }}</p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Screenshot Modal -->
    <div v-if="showScreenshotModal" class="modal" @click="closeModal">
      <div class="modal-content" @click.stop>
        <button class="modal-close" @click="closeModal">×</button>
        <img
          :src="'data:image/png;base64,' + selectedScreenshot"
          alt="Full Screenshot"
          class="modal-image"
        />
      </div>
    </div>
  </div>
</template>

<script setup>
// Vue 3 Composition API - <script setup> syntax
// This provides better TypeScript support and more concise code

import { ref, computed } from "vue";
import axios from "axios";

// API Configuration
// Use environment variable for API URL (supports local dev and production)
// Fallback to relative path for Vite proxy in development
const API_BASE_URL = import.meta.env.VITE_API_URL || "/api";

// ============================================================================
// Reactive State
// ref() creates reactive references that can be mutated
// ============================================================================
const url = ref("");
const loading = ref(false);
const result = ref(null);
const error = ref(null);
const screenshotLoading = ref(false);
const screenshots = ref(null);
const screenshotError = ref(null);
const showScreenshotModal = ref(false);
const selectedScreenshot = ref(null);

// Detect current browser
const currentBrowser = computed(() => {
  const userAgent = navigator.userAgent.toLowerCase();

  // Firefox detection
  if (userAgent.includes("firefox")) {
    return "firefox";
  }

  // Chrome/Chromium detection (default for most browsers)
  // Edge, Opera, Chrome all use Chromium
  return "chrome";
});

// Browser display name
const browserDisplayName = computed(() => {
  return currentBrowser.value === "firefox" ? "Firefox" : "Chromium";
});

// ============================================================================
// Computed Properties
// computed() creates reactive derived state
// These automatically update when their dependencies change
// ============================================================================

// Validate URL format in real-time
const isValidUrl = computed(() => {
  try {
    const urlObj = new URL(url.value);
    return urlObj.protocol === "http:" || urlObj.protocol === "https:";
  } catch {
    return false;
  }
});

// Determine CSS class based on detections AND score
// PRIORITY: Trust detection counts more than the score
const riskClass = computed(() => {
  if (!result.value) return "";

  const maliciousCount = result.value.detections.malicious;

  // Force RED if any engine detects it as malicious
  if (maliciousCount >= 1) return "malicious";
  if (result.value.detections.suspicious >= 1) return "suspicious";

  // Fallback to score for edge cases
  const score = result.value.risk_score;
  if (score > 60) return "malicious";
  if (score > 30) return "suspicious";
  return "safe";
});

// Generate risk label based on detections
const riskLabel = computed(() => {
  if (!result.value) return "";

  const maliciousCount = result.value.detections.malicious;

  if (maliciousCount >= 2) return "Malicious";
  if (maliciousCount === 1) return "High Risk";

  const score = result.value.risk_score;
  if (score <= 30) return "Safe";
  if (score <= 60) return "Suspicious";
  return "Malicious";
});

// Generate contextual recommendation
const recommendation = computed(() => {
  if (!result.value) return "";

  const maliciousCount = result.value.detections.malicious;

  // If ANY engine flags it as malicious, show strong warning
  if (maliciousCount > 0) {
    return `Warning: ${maliciousCount} security vendor${
      maliciousCount > 1 ? "s" : ""
    } flagged this URL. Do NOT visit this link.`;
  }

  const score = result.value.risk_score;
  if (score <= 30) {
    return "This URL appears to be safe. However, always exercise caution when sharing personal information.";
  }
  if (score <= 60) {
    return "This URL shows suspicious characteristics. Proceed with caution and avoid entering sensitive data.";
  }
  return "This URL is likely malicious! Do not visit this site or enter any personal information.";
});

// ============================================================================
// Methods
// Functions that handle user interactions and API calls
// ============================================================================

/**
 * Scan URL using VirusTotal API through backend
 * Handles validation, API calls, and error states
 */
const scanUrl = async () => {
  // Validate URL before making API call
  if (!isValidUrl.value) {
    error.value =
      "Please enter a valid URL (must start with http:// or https://)";
    return;
  }

  // Reset state for new scan
  loading.value = true;
  error.value = null;
  result.value = null;

  try {
    // Make API request using axios
    // axios automatically handles JSON serialization and CORS
    const response = await axios.post(
      `${API_BASE_URL}/scan`,
      {
        url: url.value,
      },
      {
        timeout: 60000, // 60 second timeout for VirusTotal processing
      }
    );

    // Check if response indicates success
    if (response.data.success) {
      result.value = response.data.data;
    } else {
      error.value =
        response.data.error || "Failed to scan URL. Please try again.";
    }
  } catch (err) {
    console.error("Scan error:", err);

    // Handle different error types with specific messages
    if (err.code === "ECONNABORTED") {
      error.value =
        "Request timed out. The URL might be taking too long to scan.";
    } else if (err.response) {
      // Server responded with error status
      const status = err.response.status;
      if (status === 429) {
        error.value =
          "Rate limit exceeded. Please wait a moment and try again.";
      } else if (status === 400) {
        error.value = err.response.data.error || "Invalid URL format.";
      } else {
        error.value = err.response.data.error || "Server error occurred.";
      }
    } else if (err.request) {
      // Request made but no response received
      error.value =
        "Cannot connect to server. Make sure the backend is running.";
    } else {
      // Something else went wrong
      error.value = "An unexpected error occurred.";
    }
  } finally {
    // Always reset loading state
    loading.value = false;
  }
};

/**
 * Format ISO timestamp to human-readable date
 * @param {string} dateString - ISO format date string
 * @returns {string} Localized date/time string
 */
const formatDate = (dateString) => {
  const date = new Date(dateString);
  return date.toLocaleString();
};

/**
 * Capture screenshot using current browser engine
 */
const captureScreenshots = async () => {
  if (!result.value) return;

  screenshotLoading.value = true;
  screenshotError.value = null;
  screenshots.value = null;

  try {
    const response = await axios.post(
      `${API_BASE_URL}/screenshot`,
      {
        url: url.value,
        browser: currentBrowser.value, // Use detected browser
      },
      {
        timeout: 30000, // 30 second timeout for screenshot capture
      }
    );

    if (response.data.success) {
      screenshots.value = response.data.data;
    } else {
      screenshotError.value =
        response.data.error || "Failed to capture screenshot.";
    }
  } catch (err) {
    console.error("Screenshot error:", err);

    if (err.code === "ECONNABORTED") {
      screenshotError.value = "Screenshot capture timed out.";
    } else if (err.response) {
      const status = err.response.status;
      if (status === 429) {
        screenshotError.value = "Rate limit exceeded. Please wait a moment.";
      } else {
        screenshotError.value =
          err.response.data.error || "Failed to capture screenshot.";
      }
    } else if (err.request) {
      screenshotError.value = "Cannot connect to server.";
    } else {
      screenshotError.value = "An unexpected error occurred.";
    }
  } finally {
    screenshotLoading.value = false;
  }
};

/**
 * Open screenshot modal
 */
const openModal = (screenshot, browser) => {
  selectedScreenshot.value = screenshot;
  showScreenshotModal.value = true;
};

/**
 * Close screenshot modal
 */
const closeModal = () => {
  showScreenshotModal.value = false;
  selectedScreenshot.value = null;
};

/**
 * Get severity icon for threat indicators
 */
const getSeverityIcon = (severity) => {
  const icons = {
    critical: "🚨",
    high: "⚠️",
    medium: "⚡",
    low: "ℹ️"
  };
  return icons[severity] || "ℹ️";
};
</script>

<style scoped>
/* ============================================================================
   Scoped Styles - Dark theme inspired by brand catalog
   Color palette: #1b1b1b, #242424, #ffffff, #ff9000, #969696, #c6c6c6
   ============================================================================ */

.scanner-container {
  max-width: 700px;
  width: 100%;
  background: #1b1b1b;
  backdrop-filter: blur(10px);
  border-radius: 10px;
  padding: 40px;
  box-shadow: 0 1px 2px 0px rgba(0, 0, 0, 0.2);
  border: 1px solid #242424;
}

/* Header Section */
.header {
  text-align: center;
  margin-bottom: 30px;
}

.header h1 {
  font-size: 2rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 10px;
  font-family: "Open Sans", Arial, sans-serif;
}

.header p {
  font-size: 1rem;
  color: #969696;
  font-family: Arial, Helvetica, sans-serif;
}

/* Input Section */
.input-section {
  display: flex;
  gap: 10px;
  margin-bottom: 30px;
}

.url-input {
  flex: 1;
  padding: 15px 20px;
  font-size: 1rem;
  background: #252525;
  color: #ffffff;
  border: 1px solid #2f2f2f;
  border-radius: 4px;
  outline: none;
  transition: all 0.3s ease;
  font-family: Arial, Helvetica, sans-serif;
}

.url-input:focus {
  border-color: #ff9000;
  box-shadow: 0 0 1px #ff9000;
}

.url-input:disabled {
  background-color: #1f1f1f;
  cursor: not-allowed;
  opacity: 0.6;
}

.url-input::placeholder {
  color: #767676;
}

.scan-button {
  padding: 15px 30px;
  font-size: 1rem;
  font-weight: 700;
  color: #ffffff;
  background: #ff9000;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.3s ease;
  white-space: nowrap;
  font-family: Arial, Helvetica, sans-serif;
}

.scan-button:hover:not(:disabled) {
  background: #e68200;
  transform: translateY(-1px);
  box-shadow: 0 4px 8px rgba(255, 144, 0, 0.3);
}

.scan-button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  transform: none;
}

.scan-button.loading {
  animation: pulse 1.5s ease-in-out infinite;
}

/* Loading Spinner */
.loading-spinner {
  text-align: center;
  padding: 40px;
}

.spinner {
  width: 50px;
  height: 50px;
  margin: 0 auto 20px;
  border: 4px solid #2f2f2f;
  border-top-color: #ff9000;
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

.loading-spinner p {
  color: #969696;
  font-size: 0.95rem;
  font-family: Arial, Helvetica, sans-serif;
}

/* Error Message */
.error-message {
  background: #2f2f2f;
  border: 2px solid #ff9000;
  border-radius: 4px;
  padding: 20px;
  display: flex;
  align-items: center;
  gap: 15px;
  margin-bottom: 20px;
}

.error-icon {
  font-size: 1.5rem;
  color: #ff9000;
}

.error-message p {
  color: #ffffff;
  font-weight: 500;
  margin: 0;
  font-family: Arial, Helvetica, sans-serif;
}

/* Results Section */
.results-section {
  animation: slideUp 0.4s ease-out;
}

.risk-badge {
  text-align: center;
  padding: 30px;
  border-radius: 10px;
  margin-bottom: 25px;
  transition: all 0.3s ease;
  border: 2px solid;
}

.risk-badge.safe {
  background: #1f1f1f;
  border-color: #10b981;
}

.risk-badge.suspicious {
  background: #1f1f1f;
  border-color: #ff9000;
}

.risk-badge.malicious {
  background: #1f1f1f;
  border-color: #ef4444;
}

.risk-score {
  font-size: 4rem;
  font-weight: 700;
  color: #ffffff;
  line-height: 1;
  margin-bottom: 10px;
  font-family: Arial, Helvetica, sans-serif;
}

.risk-label {
  font-size: 1.5rem;
  font-weight: 700;
  color: #c6c6c6;
  font-family: Arial, Helvetica, sans-serif;
}

/* URL Display */
.url-display {
  background: #242424;
  padding: 20px;
  border-radius: 4px;
  margin-bottom: 25px;
  word-break: break-all;
  border: 1px solid #2f2f2f;
}

.url-display strong {
  display: block;
  margin-bottom: 8px;
  color: #c6c6c6;
  font-family: Arial, Helvetica, sans-serif;
}

.url-display a {
  color: #ff9000;
  text-decoration: none;
  transition: color 0.2s;
  font-family: Arial, Helvetica, sans-serif;
}

.url-display a:hover {
  color: #e68200;
  text-decoration: none;
}

.url-display a:hover {
  color: #e68200;
  text-decoration: none;
}

/* Detection Details */
.detection-details {
  margin-bottom: 25px;
}

.detection-details h3 {
  font-size: 1.1rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 15px;
  font-family: Arial, Helvetica, sans-serif;
}

.detection-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 15px;
}

.detection-item {
  background: #242424;
  padding: 20px;
  border-radius: 4px;
  text-align: center;
  border: 2px solid;
  transition: all 0.3s ease;
}

.detection-item:hover {
  transform: translateY(-2px);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
}

.detection-item.malicious {
  border-color: #ef4444;
}

.detection-item.suspicious {
  border-color: #ff9000;
}

.detection-item.clean {
  border-color: #10b981;
}

.detection-item.total {
  border-color: #767676;
}

.detection-item .count {
  display: block;
  font-size: 2rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 5px;
  font-family: Arial, Helvetica, sans-serif;
}

.detection-item .label {
  display: block;
  font-size: 0.875rem;
  color: #969696;
  font-weight: 500;
  font-family: Arial, Helvetica, sans-serif;
  color: #1e293b;
  margin-bottom: 5px;
}

.detection-item .label {
  display: block;
  font-size: 0.875rem;
  color: #64748b;
  font-weight: 500;
}

/* Infrastructure Information */
.infrastructure-info {
  margin-bottom: 25px;
}

.infrastructure-info h3 {
  font-size: 1.1rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 15px;
  font-family: Arial, Helvetica, sans-serif;
}

.info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 15px;
}

.info-item {
  background: #242424;
  padding: 15px 20px;
  border-radius: 4px;
  border: 1px solid #2f2f2f;
  transition: all 0.3s ease;
}

.info-item:hover {
  transform: translateY(-2px);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
  border-color: #ff9000;
}

.info-label {
  display: block;
  font-size: 0.85rem;
  color: #969696;
  font-weight: 700;
  margin-bottom: 8px;
  font-family: Arial, Helvetica, sans-serif;
}

.info-value {
  display: block;
  font-size: 1rem;
  color: #ffffff;
  font-weight: 500;
  word-break: break-all;
  font-family: Arial, Helvetica, sans-serif;
}

/* Categories */
.categories {
  margin-bottom: 25px;
}

.categories h3 {
  font-size: 1.1rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 15px;
  font-family: Arial, Helvetica, sans-serif;
}

.category-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

.category-tag {
  background: #2f2f2f;
  color: #ff9000;
  padding: 8px 16px;
  border-radius: 4px;
  font-size: 0.875rem;
  font-weight: 700;
  border: 1px solid #ff9000;
  font-family: Arial, Helvetica, sans-serif;
}

/* Metadata */
.metadata {
  background: #242424;
  padding: 15px 20px;
  border-radius: 4px;
  margin-bottom: 20px;
  border: 1px solid #2f2f2f;
}

.metadata p {
  margin: 5px 0;
  color: #969696;
  font-size: 0.9rem;
  font-family: Arial, Helvetica, sans-serif;
}

.metadata strong {
  color: #c6c6c6;
}

.cached-badge {
  background: #2f2f2f;
  color: #ff9000;
  padding: 4px 12px;
  border-radius: 4px;
  font-size: 0.85rem;
  font-weight: 700;
  border: 1px solid #ff9000;
  font-family: Arial, Helvetica, sans-serif;
  margin-right: 8px;
}

.info-badge {
  background: #2f2f2f;
  color: #10b981;
  padding: 4px 12px;
  border-radius: 4px;
  font-size: 0.85rem;
  font-weight: 700;
  border: 1px solid #10b981;
  font-family: Arial, Helvetica, sans-serif;
  margin-right: 8px;
}

/* Threat Intelligence Indicators */
.threat-indicators {
  margin-bottom: 25px;
  padding: 20px;
  background: #242424;
  border-radius: 4px;
  border: 2px solid #ff9000;
}

.threat-indicators h3 {
  font-size: 1.1rem;
  font-weight: 700;
  color: #ff9000;
  margin-bottom: 15px;
  font-family: Arial, Helvetica, sans-serif;
}

.indicators-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
  margin-bottom: 15px;
}

.indicator-item {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 12px 15px;
  background: #1f1f1f;
  border-radius: 4px;
  border-left: 4px solid;
  transition: all 0.3s ease;
}

.indicator-item:hover {
  transform: translateX(5px);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
}

.indicator-item.severity-critical {
  border-left-color: #ef4444;
}

.indicator-item.severity-high {
  border-left-color: #ff9000;
}

.indicator-item.severity-medium {
  border-left-color: #f59e0b;
}

.indicator-item.severity-low {
  border-left-color: #10b981;
}

.indicator-icon {
  font-size: 1.5rem;
  line-height: 1;
  flex-shrink: 0;
}

.indicator-content {
  flex: 1;
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 10px;
}

.indicator-message {
  color: #ffffff;
  font-size: 0.9rem;
  font-weight: 500;
  font-family: Arial, Helvetica, sans-serif;
}

.indicator-risk {
  color: #ef4444;
  font-size: 0.85rem;
  font-weight: 700;
  white-space: nowrap;
  font-family: Arial, Helvetica, sans-serif;
}

.threat-recommendation {
  padding: 15px;
  background: #2f2f2f;
  border-radius: 4px;
  border: 1px solid #ff9000;
  color: #ffffff;
  font-size: 0.9rem;
  line-height: 1.5;
  font-family: Arial, Helvetica, sans-serif;
}

.threat-recommendation strong {
  color: #ff9000;
}

/* Recommendation */
.recommendation {
  padding: 20px;
  border-radius: 4px;
  font-weight: 500;
  text-align: center;
  border: 2px solid;
  font-family: Arial, Helvetica, sans-serif;
}

.recommendation.safe {
  background: #1f1f1f;
  color: #10b981;
  border-color: #10b981;
}

.recommendation.suspicious {
  background: #1f1f1f;
  color: #ff9000;
  border-color: #ff9000;
}

.recommendation.malicious {
  background: #1f1f1f;
  color: #ef4444;
  border-color: #ef4444;
}

.recommendation p {
  margin: 0;
}

/* Visual Sandbox */
.visual-sandbox {
  margin-top: 30px;
  padding: 25px;
  background: #242424;
  border-radius: 4px;
  border: 1px solid #2f2f2f;
}

.visual-sandbox h3 {
  font-size: 1.1rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 8px;
  font-family: Arial, Helvetica, sans-serif;
}

.sandbox-description {
  color: #969696;
  font-size: 0.9rem;
  margin-bottom: 20px;
  font-family: Arial, Helvetica, sans-serif;
}

.capture-button {
  padding: 12px 24px;
  font-size: 0.95rem;
  font-weight: 700;
  color: #ffffff;
  background: #ff9000;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.3s ease;
  font-family: Arial, Helvetica, sans-serif;
  margin-bottom: 20px;
}

.capture-button:hover:not(:disabled) {
  background: #e68200;
  transform: translateY(-1px);
  box-shadow: 0 4px 8px rgba(255, 144, 0, 0.3);
}

.capture-button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.screenshot-loading {
  text-align: center;
  padding: 30px;
}

.screenshot-loading p {
  color: #969696;
  font-size: 0.9rem;
  margin-top: 15px;
  font-family: Arial, Helvetica, sans-serif;
}

.screenshot-container {
  margin-top: 20px;
}

.screenshot-item {
  background: #1f1f1f;
  border-radius: 4px;
  border: 1px solid #2f2f2f;
  overflow: hidden;
}

.screenshot-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 15px;
  background: #242424;
  border-bottom: 1px solid #2f2f2f;
}

.browser-name {
  font-weight: 700;
  color: #ffffff;
  font-size: 1rem;
  font-family: Arial, Helvetica, sans-serif;
}

.status-badge {
  padding: 4px 12px;
  border-radius: 4px;
  font-size: 0.8rem;
  font-weight: 700;
  font-family: Arial, Helvetica, sans-serif;
}

.status-badge.success {
  background: #1f1f1f;
  color: #10b981;
  border: 1px solid #10b981;
}

.status-badge.failed {
  background: #1f1f1f;
  color: #ef4444;
  border: 1px solid #ef4444;
}

.screenshot-preview {
  position: relative;
  cursor: pointer;
  overflow: hidden;
}

.screenshot-preview img {
  width: 100%;
  height: auto;
  display: block;
  transition: transform 0.3s ease;
}

.screenshot-preview:hover img {
  transform: scale(1.05);
}

.preview-overlay {
  position: absolute;
  inset: 0;
  background: rgba(0, 0, 0, 0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  opacity: 0;
  transition: opacity 0.3s ease;
}

.screenshot-preview:hover .preview-overlay {
  opacity: 1;
}

.preview-overlay span {
  color: #ffffff;
  font-size: 1rem;
  font-weight: 700;
  font-family: Arial, Helvetica, sans-serif;
}

.screenshot-error {
  padding: 20px;
  color: #ef4444;
  text-align: center;
  font-size: 0.9rem;
  font-family: Arial, Helvetica, sans-serif;
}

/* Modal */
.modal {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.9);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  animation: fadeIn 0.3s ease;
}

.modal-content {
  position: relative;
  max-width: 95vw;
  max-height: 95vh;
  background: #1b1b1b;
  border-radius: 8px;
  padding: 10px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
}

.modal-close {
  position: absolute;
  top: -15px;
  right: -15px;
  width: 40px;
  height: 40px;
  border-radius: 50%;
  background: #ff9000;
  color: #ffffff;
  border: none;
  font-size: 24px;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.3s ease;
  z-index: 1001;
}

.modal-close:hover {
  background: #e68200;
  transform: rotate(90deg);
}

.modal-image {
  max-width: 100%;
  max-height: 90vh;
  display: block;
  border-radius: 4px;
}

@keyframes fadeIn {
  from {
    opacity: 0;
  }
  to {
    opacity: 1;
  }
}

/* Animations */
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

@keyframes pulse {
  0%,
  100% {
    opacity: 1;
  }
  50% {
    opacity: 0.7;
  }
}

@keyframes slideUp {
  from {
    opacity: 0;
    transform: translateY(20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

/* Responsive Design */
@media (max-width: 768px) {
  .scanner-container {
    padding: 25px;
    border-radius: 15px;
  }

  .header h1 {
    font-size: 1.5rem;
  }

  .input-section {
    flex-direction: column;
  }

  .scan-button {
    width: 100%;
  }

  .risk-score {
    font-size: 3rem;
  }

  .detection-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (max-width: 480px) {
  .scanner-container {
    padding: 20px;
  }

  .header h1 {
    font-size: 1.3rem;
  }

  .risk-score {
    font-size: 2.5rem;
  }

  .risk-label {
    font-size: 1.2rem;
  }
}
</style>
