export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        'soc-bg':     'rgb(var(--soc-bg) / <alpha-value>)',
        'soc-panel':  'rgb(var(--soc-panel) / <alpha-value>)',
        'soc-border': 'rgb(var(--soc-border) / <alpha-value>)',
        'soc-accent': 'rgb(var(--soc-accent) / <alpha-value>)',
        'soc-green':  'rgb(var(--soc-green) / <alpha-value>)',
        'soc-red':    'rgb(var(--soc-red) / <alpha-value>)',
        'soc-yellow': 'rgb(var(--soc-yellow) / <alpha-value>)',
        'soc-purple': 'rgb(var(--soc-purple) / <alpha-value>)',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
}
