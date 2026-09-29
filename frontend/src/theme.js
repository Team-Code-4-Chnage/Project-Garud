import { useState, useEffect } from "react";

const THEME_STORAGE_KEY = "garud-theme";

export function getInitialTheme() {
  if (typeof window === "undefined") return "dark";
  try {
    const saved = localStorage.getItem(THEME_STORAGE_KEY);
    if (saved === "light" || saved === "dark") return saved;
  } catch {}
  return "dark";
}

export function applyTheme(theme) {
  if (typeof document === "undefined") return;
  const targetTheme = theme === "light" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", targetTheme);
  try {
    localStorage.setItem(THEME_STORAGE_KEY, targetTheme);
  } catch {}
  window.dispatchEvent(new CustomEvent("garud-theme-change", { detail: { theme: targetTheme } }));
}

export function useTheme() {
  const [theme, setThemeState] = useState(getInitialTheme);

  useEffect(() => {
    // Initial sync
    const current = getInitialTheme();
    document.documentElement.setAttribute("data-theme", current);

    const handleThemeChange = (e) => {
      if (e?.detail?.theme) {
        setThemeState(e.detail.theme);
      }
    };

    window.addEventListener("garud-theme-change", handleThemeChange);
    return () => window.removeEventListener("garud-theme-change", handleThemeChange);
  }, []);

  const setTheme = (newTheme) => {
    applyTheme(newTheme);
    setThemeState(newTheme);
  };

  return { theme, setTheme, isDark: theme === "dark" };
}
