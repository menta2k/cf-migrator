#!/usr/bin/env python3
"""
Cloudflare WAF Rules Inspector
See exactly what rules exist in your zone.
"""

import requests
import json
import argparse
import sys


def inspect_zone(api_token, zone_id):
    """Inspect all WAF rulesets in a zone."""
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }
    
    base_url = "https://api.cloudflare.com/client/v4"
    
    # Get zone name
    resp = requests.get(f"{base_url}/zones/{zone_id}", headers=headers)
    zone_data = resp.json()
    if zone_data.get("success"):
        zone_name = zone_data["result"]["name"]
        print(f"\n{'='*70}")
        print(f"Zone: {zone_name} ({zone_id})")
        print(f"{'='*70}\n")
    
    # Get all rulesets
    resp = requests.get(f"{base_url}/zones/{zone_id}/rulesets", headers=headers)
    result = resp.json()
    
    if not result.get("success"):
        print(f"Error: {result.get('errors')}")
        return
    
    rulesets = result.get("result", [])
    print(f"Found {len(rulesets)} rulesets:\n")
    
    for rs in rulesets:
        print(f"📁 {rs.get('name', 'Unnamed')}")
        print(f"   ID: {rs.get('id')}")
        print(f"   Phase: {rs.get('phase')}")
        print(f"   Kind: {rs.get('kind')}")
        
        # Get full ruleset details
        rs_resp = requests.get(
            f"{base_url}/zones/{zone_id}/rulesets/{rs['id']}", 
            headers=headers
        )
        rs_data = rs_resp.json()
        
        if rs_data.get("success"):
            rules = rs_data["result"].get("rules", [])
            print(f"   Rules: {len(rules)}")
            
            if rules:
                print(f"\n   Rules detail:")
                for i, rule in enumerate(rules, 1):
                    rule_type = "MANAGED" if rule.get("ref") else "CUSTOM"
                    enabled = "✓" if rule.get("enabled", True) else "✗"
                    action = rule.get("action", "N/A")
                    desc = rule.get("description", "No description")[:50]
                    
                    print(f"   {i}. [{rule_type}] [{enabled}] {action}: {desc}")
                    
                    # Show expression for custom rules
                    if not rule.get("ref") and rule.get("expression"):
                        expr = rule.get("expression", "")[:80]
                        print(f"      Expression: {expr}...")
                    
                    # Show if there are overrides
                    if rule.get("action_parameters", {}).get("overrides"):
                        print(f"      ⚠️  Has rule overrides")
        
        print()
    
    # Also check for custom firewall rules (legacy)
    print(f"\n{'='*70}")
    print("Checking legacy Firewall Rules (if any)...")
    print(f"{'='*70}\n")
    
    resp = requests.get(f"{base_url}/zones/{zone_id}/firewall/rules", headers=headers)
    fw_result = resp.json()
    
    if fw_result.get("success"):
        fw_rules = fw_result.get("result", [])
        if fw_rules:
            print(f"Found {len(fw_rules)} legacy firewall rules:\n")
            for rule in fw_rules:
                print(f"   • {rule.get('description', 'No description')}")
                print(f"     Action: {rule.get('action')}")
                print(f"     Filter: {rule.get('filter', {}).get('expression', 'N/A')[:60]}...")
                print()
        else:
            print("No legacy firewall rules found.")
    else:
        print(f"Could not fetch legacy rules: {fw_result.get('errors')}")


def main():
    parser = argparse.ArgumentParser(description="Inspect Cloudflare WAF rules")
    parser.add_argument("--token", required=True, help="Cloudflare API token")
    parser.add_argument("--zone", required=True, help="Zone ID to inspect")
    
    args = parser.parse_args()
    inspect_zone(args.token, args.zone)


if __name__ == "__main__":
    main()
