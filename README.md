# AUREA Inventory

Custom integration for Home Assistant that creates a sanitized inventory of entities,
devices, areas and automation configurations, then optionally synchronizes the JSON file
to a private GitHub repository.

## Privacy

The exporter redacts credentials, URLs, IPv4/IPv6 addresses, MAC addresses, SSIDs,
location data and sensitive automation values. Entity IDs are intentionally preserved
because they are required for audits and ready-to-use Home Assistant YAML.

This public repository contains only the integration source code. It never contains the
generated inventory or a GitHub token.

## Installation with HACS

1. In HACS, add `https://github.com/giuseppetiso/AUREA-Inventory` as a custom repository.
2. Select the `Integration` category.
3. Download AUREA Inventory and restart Home Assistant.

## Configuration

Add the integration to `configuration.yaml` and keep the token in `secrets.yaml`:

```yaml
aurea_inventory:
  github_token: !secret aurea_inventory_github_token
  github_repository: owner/private-home-assistant-repository
  github_path: inventory/aurea_inventory.json
```

The integration registers these actions:

- `aurea_inventory.refresh`: rebuild the local inventory.
- `aurea_inventory.sync_github`: rebuild and synchronize it to GitHub.

The local inventory is refreshed every 5 minutes and GitHub synchronization runs every
30 minutes.