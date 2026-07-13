/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class', // Support theme toggling
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#030712',      // Deepest black-gray
          card: 'rgba(17, 24, 39, 0.7)', // Glassmorphism container background
          border: 'rgba(255, 255, 255, 0.08)',
          glow: 'rgba(6, 182, 212, 0.15)', // Neon cyan glow
          cyan: '#06b6d4',      // Primary cyan
          emerald: '#10b981',   // Safe green
          amber: '#f59e0b',     // Warning amber
          rose: '#f43f5e',      // Dangerous crimson
          indigo: '#6366f1',    // Accents
          slate: '#1f2937',     // Underlay panels
        }
      },
      boxShadow: {
        'cyber-glow': '0 0 15px rgba(6, 182, 212, 0.25)',
        'threat-glow': '0 0 15px rgba(244, 63, 94, 0.3)',
      },
      backdropBlur: {
        'cyber': '12px',
      }
    },
  },
  plugins: [],
}
