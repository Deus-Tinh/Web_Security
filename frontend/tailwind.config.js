/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        carbon: "#06090f",
        panel: "#0d1421",
        cyanfire: "#42e8f6",
        acid: "#a3ff12",
        danger: "#ff4d6d"
      },
      boxShadow: {
        glow: "0 0 40px rgba(66, 232, 246, 0.16)",
        danger: "0 0 28px rgba(255, 77, 109, 0.18)"
      },
      backgroundImage: {
        grid: "linear-gradient(rgba(66,232,246,.08) 1px, transparent 1px), linear-gradient(90deg, rgba(66,232,246,.08) 1px, transparent 1px)"
      }
    }
  },
  plugins: []
};

