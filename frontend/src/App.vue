<template>
  <div class="app-container">
    <!-- Main Application Wrapper -->
    <div class="app-content">
      <Scanner />
    </div>

    <!-- Footer -->
    <footer class="app-footer">
      <p>Made by LAT, Duckie | Powered by VirusTotal API</p>
    </footer>
  </div>
</template>

<script setup>
// Vue 3 Composition API - <script setup> syntax
// This is the modern way to write Vue components
import Scanner from "./components/Scanner.vue";
</script>

<style>
/* Global Styles */
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

:root {
  --color-safe: #10b981;
  --color-suspicious: #f59e0b;
  --color-malicious: #ef4444;
  --color-background: #0f172a;
  --color-surface: #1e293b;
  --color-text: #f1f5f9;
  --color-text-secondary: #94a3b8;
  --color-border: #334155;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen,
    Ubuntu, Cantarell, sans-serif;
  background: #000000;
  color: var(--color-text);
  min-height: 100vh;
  line-height: 1.6;
}

.app-container {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  padding: 20px;
}

.app-content {
  flex: 1;
  display: flex;
  justify-content: center;
  align-items: center;
  padding: 20px 0;
}

.app-footer {
  text-align: center;
  padding: 20px;
  color: rgba(255, 255, 255, 0.7);
  font-size: 0.875rem;
}

/* Responsive Design */
@media (max-width: 768px) {
  .app-container {
    padding: 10px;
  }

  .app-content {
    padding: 10px 0;
  }
}
</style>
