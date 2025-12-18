// Vue 3 Application Entry Point
// Using Composition API throughout the application

import { createApp } from "vue";
import App from "./App.vue";

// Create and mount the Vue application
const app = createApp(App);

// Mount to DOM element with id="app"
app.mount("#app");
