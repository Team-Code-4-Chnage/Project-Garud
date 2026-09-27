/**
 * EagleIcon.jsx
 * Custom sovereign Eagle / Garud vector icon for Project Garud.
 * Designed to match Lucide icon aesthetics (24x24 viewBox, stroke-width 2, round joins).
 */
export default function EagleIcon({
  size = 18,
  color = "currentColor",
  className = "",
  style = {},
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      style={{
        display: "inline-block",
        verticalAlign: "middle",
        flexShrink: 0,
        ...style,
      }}
      aria-label="Project Garud Eagle Emblem"
    >
      {/* Eagle Head & Sharp Hook Beak */}
      <path
        d="M12 2 L13.5 3.5 C14.5 3.8 15 4.8 14 5.5 L12 6.8 L10 5.5 C9 4.8 9.5 3.8 10.5 3.5 L12 2 Z"
        fill={`${color}30`}
      />
      <path d="M12 4.2 L12 6.8" />
      <path d="M11 5.4 L12 7.2 L13 5.4" />

      {/* Outstretched Sweeping Wings (Garud Wings) */}
      {/* Left Wing */}
      <path d="M9.8 6.2 C6.8 4 3.2 3.8 1 4.5 C2.2 7.2 4.2 9.8 7.5 12 L9.5 11" />
      <path d="M2.5 6.2 C4.5 8.5 7 10.5 9.8 11.8" />
      <path d="M4.5 8 C6.5 10 8.2 11.2 10 12.2" />

      {/* Right Wing */}
      <path d="M14.2 6.2 C17.2 4 20.8 3.8 23 4.5 C21.8 7.2 19.8 9.8 16.5 12 L14.5 11" />
      <path d="M21.5 6.2 C19.5 8.5 17 10.5 14.2 11.8" />
      <path d="M19.5 8 C17.5 10 15.8 11.2 14 12.2" />

      {/* Core Torso */}
      <path d="M12 6.8 L13.8 11 L12 16 L10.2 11 Z" fill={`${color}40`} />

      {/* Tail Feathers */}
      <path d="M10.5 14.8 L8.5 21.5 L12 19.5 L15.5 21.5 L13.5 14.8" />
    </svg>
  );
}
