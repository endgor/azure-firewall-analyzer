/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'rule-dnat': '#3b82f6',
        'rule-network': '#10b981',
        'rule-application': '#f59e0b',
        'priority-high': '#ef4444',
        'priority-medium': '#f59e0b',
        'priority-low': '#10b981',
      },
    },
  },
  plugins: [],
}