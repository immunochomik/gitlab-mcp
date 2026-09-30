# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-09-30

### Added

- Policy-controlled `update_mr` action for changing a merge request title or description.

## [0.5.0] - 2026-09-28

### Added

- Policy-controlled `create_mr_note` action for posting general merge request comments.

## [0.4.0] - 2026-09-16

### Added

- Pipeline pagination and RFC3339 creation/update date filters.
- Policy-controlled `get_job` lookup by job ID with exact name and pipeline metadata.

## [0.3.0] - 2026-09-07

### Added

- Pipeline job status filters, retried-job visibility, pagination, bridge
  metadata, and policy-checked downstream pipeline traversal.
- Byte-range job trace retrieval with explicit total size and next-offset
  metadata for long logs.

## [0.2.0] - 2026-09-01

### Added

- Configurable GitLab username/password authentication through the
  `GITLAB_USER` and `GITLAB_PASSWORD` environment variables and
  `gitlab.NewBasicAuthClient`.
- Startup connectivity validation against the current-user endpoint.
- MIT license.

### Changed

- The server now exits when the startup GitLab connectivity check fails instead
  of continuing in an unusable state.

## [0.1.0] - 2026-08-30

### Added

- Initial GitLab MCP server with project policy controls, secret redaction,
  audit logging, repository and merge-request tools, pipeline and job tools,
  and HTTP and stdio transports.

[Unreleased]: https://github.com/immunochomik/gitlab-mcp/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/immunochomik/gitlab-mcp/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/immunochomik/gitlab-mcp/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/immunochomik/gitlab-mcp/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/immunochomik/gitlab-mcp/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/immunochomik/gitlab-mcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/immunochomik/gitlab-mcp/releases/tag/v0.1.0
