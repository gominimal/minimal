// Conventional Commits enforcement. See docs/commit-conventions.md.
module.exports = {
  extends: ["@commitlint/config-conventional"],
  // Dependabot writes its own bodies (changelog/compare URLs) and always
  // overruns body-max-line-length; we cannot edit them. Skip its commits.
  ignores: [(message) => message.includes("Signed-off-by: dependabot[bot]")],
  rules: {
    "type-enum": [
      2,
      "always",
      [
        "feat",
        "fix",
        "docs",
        "style",
        "refactor",
        "perf",
        "test",
        "build",
        "ci",
        "chore",
        "revert",
      ],
    ],
  },
};
