/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      animation: {
        blob: "blob 10s infinite",
      },
      keyframes:{
        blob: {
          "0%": { transform: "translate(0px, 0px) scale(1)" },
          "33%": { transform: "translate(30px, -200px) scale(1.1)" },
          "66%": { transform: "translate(-150px, 20px) scale(0.9)" },
          "100%": { transform: "translate(0px, 0px) scale(1)" },
        }
      },
      colors: {
        primary: '#1a202c', // Dark gray
        secondary: '#2d3748', // Slightly lighter gray
        accent: '#e53e3e', // Red
        textPrimary: '#ffffff', // White
      },
    },
  },
  plugins: [],
}