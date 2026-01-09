#!/usr/bin/env python3
"""
Cloudflare WAF Rules Migrator v2
Export WAF rules from one zone and import them into another.
Handles: custom rules, skip rules, and managed rule overrides.
"""

import requests
import json
import argparse
import sys
from datetime import datetime


class CloudflareWAFMigrator:
    BASE_URL = "https://api.cloudflare.com/client/v4"

    def __init__(self, api_token):
        self.api_token = api_token
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }

    def _make_request(self, method, endpoint, data=None, silent=False):
        """Make an API request to Cloudflare."""
        url = f"{self.BASE_URL}{endpoint}"
        response = requests.request(method, url, headers=self.headers, json=data)
        
        try:
            result = response.json()
        except json.JSONDecodeError:
            if not silent:
                print(f"Error: Invalid JSON response from API")
                print(f"Status code: {response.status_code}")
                print(f"Response: {response.text}")
            return None

        if not result.get("success", False):
            errors = result.get("errors", [])
            if not silent:
                print(f"API Error: {errors}")
            return None

        return result

    def get_zone_name(self, zone_id):
        """Get the zone name for a given zone ID."""
        result = self._make_request("GET", f"/zones/{zone_id}")
        if result:
            return result.get("result", {}).get("name", "Unknown")
        return "Unknown"

    def list_rulesets(self, zone_id):
        """List all rulesets for a zone."""
        result = self._make_request("GET", f"/zones/{zone_id}/rulesets")
        if result:
            return result.get("result", [])
        return []

    def get_ruleset(self, zone_id, ruleset_id, silent=False):
        """Get a specific ruleset with all its rules."""
        result = self._make_request("GET", f"/zones/{zone_id}/rulesets/{ruleset_id}", silent=silent)
        if result:
            return result.get("result", {})
        return {}

    def export_waf_rules(self, zone_id, output_file=None):
        """Export all WAF rules from a zone."""
        print(f"\n📤 Exporting WAF rules from zone: {zone_id}")
        zone_name = self.get_zone_name(zone_id)
        print(f"   Zone name: {zone_name}")

        rulesets = self.list_rulesets(zone_id)
        
        # Phases we want to migrate
        waf_phases = [
            "http_request_firewall_custom",      # Custom WAF rules
            "http_request_firewall_managed",     # Managed WAF (skip rules & overrides)
            "http_ratelimit",                    # Rate limiting rules
            "http_request_sbfm",                 # Super Bot Fight Mode
            "http_request_dynamic_redirect",     # Dynamic redirects
            "http_request_transform",            # Request transforms
            "http_response_headers_transform",   # Response header transforms
        ]

        exported_rulesets = []
        skipped_phases = []
        
        for ruleset in rulesets:
            phase = ruleset.get("phase", "")
            if phase not in waf_phases:
                continue
                
            ruleset_id = ruleset.get("id")
            full_ruleset = self.get_ruleset(zone_id, ruleset_id, silent=True)
            
            if not full_ruleset:
                # Couldn't access this ruleset (likely permissions)
                skipped_phases.append(phase)
                continue
            
            if not full_ruleset.get("rules"):
                continue
            
            # Clean up the ruleset for export
            cleaned_ruleset = self._clean_ruleset_for_export(full_ruleset)
            
            if cleaned_ruleset.get("rules"):  # Only add if there are rules to migrate
                exported_rulesets.append(cleaned_ruleset)
                
                rule_count = len(cleaned_ruleset.get("rules", []))
                print(f"   ✓ Exported: {ruleset.get('name', 'Unnamed')} ({phase}) - {rule_count} rules")

        export_data = {
            "exported_at": datetime.utcnow().isoformat(),
            "source_zone_id": zone_id,
            "source_zone_name": zone_name,
            "rulesets": exported_rulesets
        }

        if output_file:
            with open(output_file, "w") as f:
                json.dump(export_data, f, indent=2)
            print(f"\n💾 Exported to: {output_file}")
        
        total_rules = sum(len(rs.get("rules", [])) for rs in exported_rulesets)
        print(f"\n📊 Export Summary:")
        print(f"   Rulesets: {len(exported_rulesets)}")
        print(f"   Total rules: {total_rules}")
        
        if skipped_phases:
            print(f"\n⚠️  Skipped {len(skipped_phases)} rulesets (no permission or empty):")
            for phase in skipped_phases:
                print(f"      - {phase}")
            print(f"   To include these, add more permissions to your API token.")

        return export_data

    def _clean_ruleset_for_export(self, ruleset):
        """Remove zone-specific IDs and metadata from a ruleset."""
        phase = ruleset.get("phase")
        
        cleaned = {
            "name": ruleset.get("name", "Migrated Rules"),
            "description": ruleset.get("description", ""),
            "phase": phase,
            "rules": []
        }

        for rule in ruleset.get("rules", []):
            cleaned_rule = self._clean_rule_for_export(rule, phase)
            if cleaned_rule:
                cleaned["rules"].append(cleaned_rule)

        return cleaned

    def _clean_rule_for_export(self, rule, phase):
        """Clean a single rule for export."""
        action = rule.get("action")
        
        # For managed phase, we want skip rules and rules with overrides
        if phase == "http_request_firewall_managed":
            # Skip rules (WAF exceptions) - these ARE custom and should be migrated
            if action == "skip":
                return {
                    "action": "skip",
                    "expression": rule.get("expression"),
                    "description": rule.get("description", ""),
                    "enabled": rule.get("enabled", True),
                    "action_parameters": rule.get("action_parameters", {}),
                    "logging": rule.get("logging", {"enabled": True})
                }
            
            # Execute rules with overrides - these have custom managed rule settings
            if action == "execute" and rule.get("action_parameters", {}).get("overrides"):
                return {
                    "action": "execute",
                    "expression": rule.get("expression", "true"),
                    "description": rule.get("description", ""),
                    "enabled": rule.get("enabled", True),
                    "action_parameters": rule.get("action_parameters", {}),
                }
            
            # Skip pure managed rules without customization
            return None
        
        # For custom firewall phase and others
        cleaned_rule = {
            "action": action,
            "expression": rule.get("expression"),
            "description": rule.get("description", ""),
            "enabled": rule.get("enabled", True),
        }

        # Include action parameters if present
        if rule.get("action_parameters"):
            cleaned_rule["action_parameters"] = rule.get("action_parameters")

        # Include rate limiting config if present
        if rule.get("ratelimit"):
            cleaned_rule["ratelimit"] = rule.get("ratelimit")

        # Include logging config if present
        if rule.get("logging"):
            cleaned_rule["logging"] = rule.get("logging")

        return cleaned_rule

    def import_waf_rules(self, zone_id, import_data, dry_run=False):
        """Import WAF rules into a zone."""
        print(f"\n📥 Importing WAF rules to zone: {zone_id}")
        zone_name = self.get_zone_name(zone_id)
        print(f"   Zone name: {zone_name}")

        if isinstance(import_data, str):
            with open(import_data, "r") as f:
                import_data = json.load(f)

        rulesets = import_data.get("rulesets", [])
        
        if dry_run:
            print("\n🔍 DRY RUN - No changes will be made\n")

        results = []
        for ruleset in rulesets:
            phase = ruleset.get("phase")
            rules = ruleset.get("rules", [])
            
            if not rules:
                print(f"   ⏭ Skipping empty ruleset: {ruleset.get('name')}")
                continue

            print(f"\n   Processing: {ruleset.get('name')} ({phase})")
            print(f"   Rules to import: {len(rules)}")

            if dry_run:
                for rule in rules:
                    status = "enabled" if rule.get("enabled", True) else "disabled"
                    print(f"      [{status}] {rule.get('action')}: {rule.get('description', 'No description')}")
                results.append({"phase": phase, "status": "dry_run", "rules": len(rules)})
                continue

            # Check if a ruleset already exists for this phase
            existing_rulesets = self.list_rulesets(zone_id)
            existing_ruleset = next(
                (rs for rs in existing_rulesets if rs.get("phase") == phase),
                None
            )

            if existing_ruleset:
                # Update existing ruleset
                result = self._update_ruleset(zone_id, existing_ruleset["id"], ruleset, rules, phase)
            else:
                # Create new ruleset
                result = self._create_ruleset(zone_id, ruleset)

            results.append(result)

        print(f"\n📊 Import Summary:")
        success_count = sum(1 for r in results if r.get("status") == "success")
        dry_run_count = sum(1 for r in results if r.get("status") == "dry_run")
        
        if dry_run:
            print(f"   Would import: {dry_run_count} rulesets")
        else:
            print(f"   Successful: {success_count}/{len(results)}")
        
        return results

    def _create_ruleset(self, zone_id, ruleset):
        """Create a new ruleset in the destination zone."""
        payload = {
            "name": ruleset.get("name"),
            "description": ruleset.get("description", "Migrated from another zone"),
            "kind": "zone",
            "phase": ruleset.get("phase"),
            "rules": ruleset.get("rules", [])
        }

        result = self._make_request("POST", f"/zones/{zone_id}/rulesets", payload)
        
        if result:
            print(f"   ✓ Created ruleset: {ruleset.get('name')}")
            return {"phase": ruleset.get("phase"), "status": "success", "action": "created"}
        else:
            print(f"   ✗ Failed to create ruleset: {ruleset.get('name')}")
            return {"phase": ruleset.get("phase"), "status": "failed", "action": "create"}

    def _update_ruleset(self, zone_id, ruleset_id, ruleset, new_rules, phase):
        """Update an existing ruleset with new rules."""
        # Get existing ruleset
        existing = self.get_ruleset(zone_id, ruleset_id)
        existing_rules = existing.get("rules", [])
        
        # For managed phase, we need to be careful about rule ordering
        # Skip rules should come BEFORE execute rules
        if phase == "http_request_firewall_managed":
            # Separate skip rules and execute rules
            new_skip_rules = [r for r in new_rules if r.get("action") == "skip"]
            new_execute_rules = [r for r in new_rules if r.get("action") == "execute"]
            existing_skip_rules = [r for r in existing_rules if r.get("action") == "skip"]
            existing_execute_rules = [r for r in existing_rules if r.get("action") != "skip"]
            
            # Combine: new skips + existing skips + new executes + existing executes
            combined_rules = new_skip_rules + existing_skip_rules + new_execute_rules + existing_execute_rules
        else:
            # For other phases, just prepend new rules
            combined_rules = new_rules + existing_rules

        payload = {
            "rules": combined_rules
        }

        result = self._make_request("PUT", f"/zones/{zone_id}/rulesets/{ruleset_id}", payload)
        
        if result:
            print(f"   ✓ Updated ruleset: {ruleset.get('name')} (+{len(new_rules)} rules)")
            return {"phase": ruleset.get("phase"), "status": "success", "action": "updated"}
        else:
            print(f"   ✗ Failed to update ruleset: {ruleset.get('name')}")
            return {"phase": ruleset.get("phase"), "status": "failed", "action": "update"}


def main():
    parser = argparse.ArgumentParser(
        description="Export and import Cloudflare WAF rules between zones (v2)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Export rules:
    python cloudflare_waf_migrator_v2.py export --token YOUR_TOKEN --zone ZONE_ID --output rules.json

  Import rules:
    python cloudflare_waf_migrator_v2.py import --token YOUR_TOKEN --zone ZONE_ID --input rules.json

  Import with dry run (preview only):
    python cloudflare_waf_migrator_v2.py import --token YOUR_TOKEN --zone ZONE_ID --input rules.json --dry-run

  Full migration (export and import in one command):
    python cloudflare_waf_migrator_v2.py migrate --token YOUR_TOKEN --source SOURCE_ZONE --dest DEST_ZONE

Supported rule types:
  - Custom WAF rules
  - WAF Skip/Exception rules (like your js_edit_photo.php rules)
  - Managed rule overrides
  - Rate limiting rules
  - Transform rules (request/response)
  - Dynamic redirects
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Export command
    export_parser = subparsers.add_parser("export", help="Export WAF rules from a zone")
    export_parser.add_argument("--token", required=True, help="Cloudflare API token")
    export_parser.add_argument("--zone", required=True, help="Source zone ID")
    export_parser.add_argument("--output", "-o", default="waf_rules_export.json", help="Output file (default: waf_rules_export.json)")

    # Import command
    import_parser = subparsers.add_parser("import", help="Import WAF rules to a zone")
    import_parser.add_argument("--token", required=True, help="Cloudflare API token")
    import_parser.add_argument("--zone", required=True, help="Destination zone ID")
    import_parser.add_argument("--input", "-i", required=True, help="Input file with exported rules")
    import_parser.add_argument("--dry-run", action="store_true", help="Preview changes without applying them")

    # Migrate command (export + import)
    migrate_parser = subparsers.add_parser("migrate", help="Migrate WAF rules from one zone to another")
    migrate_parser.add_argument("--token", required=True, help="Cloudflare API token")
    migrate_parser.add_argument("--source", required=True, help="Source zone ID")
    migrate_parser.add_argument("--dest", required=True, help="Destination zone ID")
    migrate_parser.add_argument("--dry-run", action="store_true", help="Preview changes without applying them")
    migrate_parser.add_argument("--save-export", help="Optionally save export to file")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    migrator = CloudflareWAFMigrator(args.token)

    if args.command == "export":
        migrator.export_waf_rules(args.zone, args.output)

    elif args.command == "import":
        migrator.import_waf_rules(args.zone, args.input, dry_run=args.dry_run)

    elif args.command == "migrate":
        print("=" * 60)
        print("  Cloudflare WAF Rules Migration v2")
        print("=" * 60)
        
        # Export from source
        export_data = migrator.export_waf_rules(args.source, args.save_export)
        
        # Import to destination
        if export_data.get("rulesets"):
            migrator.import_waf_rules(args.dest, export_data, dry_run=args.dry_run)
        else:
            print("\n⚠️  No rules found to migrate")

        print("\n" + "=" * 60)
        print("  Migration Complete!")
        print("=" * 60)


if __name__ == "__main__":
    main()

