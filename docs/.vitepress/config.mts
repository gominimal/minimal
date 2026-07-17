import { withMermaid } from "vitepress-plugin-mermaid";

// Engineering docs site for the gominimal/minimal repository.
// User-facing guides and concepts live at https://docs.minimal.dev.
export default withMermaid({
  title: "Minimal",
  description:
    "Engineering documentation for Minimal: hermetic builds, sandboxed sessions, and task running.",

  // Repo-internal material stays out of the rendered site.
  srcExclude: [
    "specs/**",
    "spikes/**",
    "internal/**",
  ],

  // Dead links are build failures, by design. Do not flip this to true to
  // get a green build — fix the link instead.
  ignoreDeadLinks: false,

  head: [
    ["link", { rel: "icon", type: "image/svg+xml", href: "/favicon.svg" }],
  ],

  themeConfig: {
    // The marks are named for the artwork color, not the mode: the dark
    // (#141414) mark renders on the light background and vice versa.
    logo: {
      light: "/minimal-mark-dark.svg",
      dark: "/minimal-mark-light.svg",
    },

    nav: [
      { text: "Reference", link: "/reference/cli" },
      { text: "Architecture", link: "/architecture" },
      { text: "User guides", link: "https://docs.minimal.dev" },
    ],

    sidebar: [
      { text: "Home", link: "/" },
      {
        text: "Reference",
        items: [
          { text: "CLI overview", link: "/reference/cli" },
          { text: "mip", link: "/reference/cli-mip" },
          { text: "min", link: "/reference/cli-min" },
          { text: "minimal.toml", link: "/reference/minimal-dot-toml" },
          { text: "Tasks", link: "/reference/tasks" },
          { text: "Build specs", link: "/reference/build-specs" },
          { text: "Harness specs", link: "/reference/harness-specs" },
          { text: "Sandbox operations", link: "/reference/sandbox-operations" },
          { text: "Linux host setup", link: "/reference/linux-host-setup" },
          {
            text: "Operations",
            items: [
              { text: "minimald", link: "/reference/cli-minimald" },
              { text: "minvmd", link: "/reference/cli-minvmd" },
            ],
          },
        ],
      },
      {
        text: "Architecture",
        items: [
          { text: "Overview", link: "/architecture" },
          { text: "Session composition", link: "/arch/sessions-composition" },
          { text: "minvmd", link: "/arch/minvmd" },
        ],
      },
      {
        text: "Contributing",
        items: [
          { text: "Commit conventions", link: "/commit-conventions" },
          { text: "Rust coding standards", link: "/rust-coding-standards" },
          { text: "CI strategy", link: "/ci-strategy" },
          {
            text: "Decisions",
            items: [
              {
                text: "0001 — Rust error handling",
                link: "/decisions/0001-rust-error-handling-strategy",
              },
            ],
          },
        ],
      },
    ],

    search: { provider: "local" },

    socialLinks: [
      { icon: "github", link: "https://github.com/gominimal/minimal" },
    ],

    outline: { level: [2, 3] },
  },
});
