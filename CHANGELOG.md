# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Configurable GitLab username/password authentication through the
  `GITLAB_USER` and `GITLAB_PASSWORD` environment variables and
  `gitlab.NewBasicAuthClient`.
- Startup connectivity validation against the current-user endpoint.

### Changed

- The server now exits when the startup GitLab connectivity check fails instead
  of continuing in an unusable state.

## [0.1.0] - 2026-08-30

### Added

- Initial GitLab MCP server with project policy controls, secret redaction,
  audit logging, repository and merge-request tools, pipeline and job tools,
  and HTTP and stdio transports.

[Unreleased]: https://github.com/immunochomik/gitlab-mcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/immunochomik/gitlab-mcp/releases/tag/v0.1.0
