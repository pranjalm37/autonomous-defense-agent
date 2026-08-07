import type { Config } from "tailwindcss";

/* Operator-console theme — colors resolve to the CSS variables in src/index.css */
const hsl = (v: string) => `hsl(var(${v}) / <alpha-value>)`;

const config: Config = {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    container: { center: true, padding: "1.5rem" },
    extend: {
      colors: {
        // surfaces
        void: hsl("--void"),
        pane: { DEFAULT: hsl("--pane"), 2: hsl("--pane-2"), 3: hsl("--pane-3") },
        rule: { DEFAULT: hsl("--rule"), 2: hsl("--rule-2") },
        // text ramp
        ink: { DEFAULT: hsl("--ink"), 2: hsl("--ink-2"), 3: hsl("--ink-3") },
        // the only hues in the system
        sev: {
          critical: hsl("--sev-critical"),
          high: hsl("--sev-high"),
          medium: hsl("--sev-medium"),
          low: hsl("--sev-low"),
          info: hsl("--sev-info"),
        },
        ok: hsl("--ok"),

        // shadcn-compatible aliases
        border: hsl("--border"),
        input: hsl("--input"),
        ring: hsl("--ring"),
        background: hsl("--background"),
        foreground: hsl("--foreground"),
        primary: { DEFAULT: hsl("--primary"), foreground: hsl("--primary-foreground") },
        secondary: { DEFAULT: hsl("--secondary"), foreground: hsl("--secondary-foreground") },
        destructive: { DEFAULT: hsl("--destructive"), foreground: hsl("--destructive-foreground") },
        muted: { DEFAULT: hsl("--muted"), foreground: hsl("--muted-foreground") },
        accent: { DEFAULT: hsl("--accent"), foreground: hsl("--accent-foreground") },
        card: { DEFAULT: hsl("--card"), foreground: hsl("--card-foreground") },
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "var(--radius)",
        sm: "var(--radius)",
      },
      fontFamily: {
        sans: ["Instrument Sans", "-apple-system", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      fontSize: {
        "2xs": ["9.5px", { lineHeight: "1.3" }],
        xs: ["10.5px", { lineHeight: "1.4" }],
        sm: ["12px", { lineHeight: "1.45" }],
        base: ["13px", { lineHeight: "1.45" }],
        lg: ["15px", { lineHeight: "1.35" }],
        xl: ["18px", { lineHeight: "1.3" }],
        "2xl": ["22px", { lineHeight: "1.25" }],
        "3xl": ["30px", { lineHeight: "1.1" }],
      },
      keyframes: {
        "accordion-down": { from: { height: "0" }, to: { height: "var(--radix-accordion-content-height)" } },
        "accordion-up": { from: { height: "var(--radix-accordion-content-height)" }, to: { height: "0" } },
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
};

export default config;
