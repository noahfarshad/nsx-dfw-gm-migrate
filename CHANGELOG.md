# Changelog

All notable changes to this project are documented here.

## [1.0.0] — 2026-09-30

### Added

- Initial public release. Export a distributed firewall from one NSX Global Manager, plan the move, and stage every policy disabled. Apply does not write without --commit. TLS verification stays on.

### Notes

- All customer-specific identifiers have been replaced with generic example values.
- Configuration files use placeholder credentials (ChangeMe!) that must be replaced with your own before use.
- Hostnames follow the *.example.com pattern and IP addresses use the RFC 5737 documentation range (192.0.2.0/24).
