/** @type {import('tailwindcss').Config} */
export default {
    content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
    theme: {
        extend: {
            colors: {
                'security-primary': '#38bdf8',
                'security-card': '#1e293b',
                'security-border': '#334155',
            },
        },
    },
    plugins: [],
    corePlugins: { preflight: false },
}