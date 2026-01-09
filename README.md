# Cloudflare WAF Rules Migrator

Export and import Cloudflare WAF rules between zones. Supports custom rules, skip rules (WAF exceptions), managed rule overrides, and more.

## Features

- Export WAF rules from any zone to JSON
- Import rules into another zone
- Direct zone-to-zone migration
- Dry run mode to preview changes
- Handles skip rules and managed rule overrides
- Preserves rule enabled/disabled state

## Supported Rule Types

| Rule Type | Phase | Supported |
|-----------|-------|-----------|
| Custom WAF rules | `http_request_firewall_custom` | ✅ |
| WAF skip/exception rules | `http_request_firewall_managed` | ✅ |
| Managed rule overrides | `http_request_firewall_managed` | ✅ |
| Rate limiting rules | `http_ratelimit` | ✅ |
| Super Bot Fight Mode | `http_request_sbfm` | ✅ |
| Transform rules | `http_request_transform` | ✅ |
| Response header transforms | `http_response_headers_transform` | ✅ |
| Dynamic redirects | `http_request_dynamic_redirect` | ✅ |

## Requirements

- Python 3.7+
- `requests` library

## Installation

```bash
pip install -r requirements.txt
```

## API Token Setup

Create a Cloudflare API token at: https://dash.cloudflare.com/profile/api-tokens

### Required Permissions

| Permission | Access |
|------------|--------|
| Zone > Zone | Read |
| Zone > Firewall Services | Edit |
| Zone > Zone WAF | Edit |

### Optional Permissions (for additional rule types)

| Permission | For |
|------------|-----|
| Zone > Transform Rules > Edit | Request/response transforms |
| Zone > Page Rules > Edit | Dynamic redirects |
| Zone > Config Rules > Edit | Configuration rules |

### Zone Resources

Make sure your token has access to **both** source and destination zones:
- Select "Include > Specific zone" and add both zones, OR
- Select "Include > All zones"

## Usage

### Export Rules

Export WAF rules from a zone to a JSON file:

```bash
python cloudflare_waf_migrator_v2.py export \
  --token YOUR_API_TOKEN \
  --zone SOURCE_ZONE_ID \
  --output rules.json
```

### Import Rules

Import rules from a JSON file into a zone:

```bash
python cloudflare_waf_migrator_v2.py import \
  --token YOUR_API_TOKEN \
  --zone DEST_ZONE_ID \
  --input rules.json
```

### Preview Import (Dry Run)

Preview what would be imported without making changes:

```bash
python cloudflare_waf_migrator_v2.py import \
  --token YOUR_API_TOKEN \
  --zone DEST_ZONE_ID \
  --input rules.json \
  --dry-run
```

### Direct Migration

Export and import in one command:

```bash
python cloudflare_waf_migrator_v2.py migrate \
  --token YOUR_API_TOKEN \
  --source SOURCE_ZONE_ID \
  --dest DEST_ZONE_ID
```

With dry run:

```bash
python cloudflare_waf_migrator_v2.py migrate \
  --token YOUR_API_TOKEN \
  --source SOURCE_ZONE_ID \
  --dest DEST_ZONE_ID \
  --dry-run
```

Save export to file during migration:

```bash
python cloudflare_waf_migrator_v2.py migrate \
  --token YOUR_API_TOKEN \
  --source SOURCE_ZONE_ID \
  --dest DEST_ZONE_ID \
  --save-export backup.json
```

## Inspect Tool

Use the inspector to see all rules in a zone:

```bash
python inspect_waf.py --token YOUR_API_TOKEN --zone ZONE_ID
```

This shows:
- All rulesets and their phases
- Each rule marked as CUSTOM or MANAGED
- Enabled/disabled status
- Rule expressions
- Legacy firewall rules (if any)

## Finding Your Zone ID

1. Go to the Cloudflare dashboard
2. Select your domain
3. Scroll down on the Overview page
4. Find "Zone ID" in the right sidebar under "API"

## Troubleshooting

### "Unauthorized to access requested resource"

Your API token doesn't have access to the zone. Make sure:
- Token permissions include the destination zone
- Token has "Zone > Firewall Services > Edit" permission

### "Skipped rulesets (no permission or empty)"

This usually means:
1. The ruleset is empty (no rules configured) - safe to ignore
2. Your token needs additional permissions for that rule type

Use `inspect_waf.py` to check if the ruleset actually has rules.

### Rules not appearing after import

- Check if rules were imported as disabled
- Verify in Cloudflare dashboard under Security > WAF
- Some rules may require zone-specific configuration

## Example Output

```
============================================================
  Cloudflare WAF Rules Migration v2
============================================================

📤 Exporting WAF rules from zone: AAAAAAAAAAAAAAAAAAAAAAAA
   Zone name: example.com
   ✓ Exported: default (http_request_firewall_custom) - 17 rules
   ✓ Exported: default (http_request_firewall_managed) - 14 rules

📊 Export Summary:
   Rulesets: 2
   Total rules: 31

📥 Importing WAF rules to zone: BBBBBBBBBBBBBBBBBBBBBBBBBBB
   Zone name: example2.com

   Processing: default (http_request_firewall_custom)
   Rules to import: 17
   ✓ Updated ruleset: default (+17 rules)

   Processing: default (http_request_firewall_managed)
   Rules to import: 14
   ✓ Updated ruleset: default (+14 rules)

📊 Import Summary:
   Successful: 2/2

============================================================
  Migration Complete!
============================================================
```

## Files

| File | Description |
|------|-------------|
| `cloudflare_waf_migrator.py` | Main migration tool |
| `inspect_waf.py` | Inspect rules in a zone |
| `requirements.txt` | Python dependencies |

## License

MIT License - feel free to use and modify.
