/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: {
          primary: '#0F172A',
          secondary: '#1E293B',
          card: '#334155',
        },
        text: {
          primary: '#F8FAFC',
          secondary: '#94A3B8',
        },
        accent: {
          blue: '#3B82F6',
          red: '#EF4444',
          amber: '#F59E0B',
          green: '#22C55E',
          purple: '#A855F7',
          orange: '#F97316',
        },
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        display: ['Space Grotesk', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
    },
  },
  plugins: [],
}
