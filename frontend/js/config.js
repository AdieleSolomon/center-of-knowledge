// Configuration for different environments
const config = {
    development: {
        API_BASE: 'http://localhost:5000/api'
    },
    production: {
        API_BASE: 'https://your-render-app.onrender.com/api'
    }
};

// Detect environment
const isDevelopment = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
const currentConfig = isDevelopment ? config.development : config.production;

// Global API Base URL
window.API_BASE = currentConfig.API_BASE;
console.log('🔧 Environment:', isDevelopment ? 'Development' : 'Production');
console.log('🌐 API Base:', window.API_BASE);