#!/usr/bin/env python3
"""
cli.py
------
Command-line interface for managing WAF rules.

Usage:
    python cli.py list
    python cli.py add --type "SQL Injection" --pattern "new pattern" --score 10
    python cli.py update --id "SQLI-001" --pattern "updated pattern"
    python cli.py delete --id "SQLI-001"
"""

import json
import argparse
import os
import uuid

RULES_FILE = os.path.join(os.path.dirname(__file__), "rules", "rules.json")

def load_rules():
    with open(RULES_FILE, "r") as f:
        return json.load(f)

def save_rules(data):
    with open(RULES_FILE, "w") as f:
        json.dump(data, f, indent=2)

def list_rules():
    data = load_rules()
    for rule in data["rules"]:
        print(f"ID: {rule['id']}, Type: {rule['type']}, Score: {rule['score']}")
        print(f"Patterns: {rule['patterns']}")
        print("-" * 50)

def add_rule(rule_type, pattern, score):
    data = load_rules()
    # Generate new ID
    ids = [r["id"] for r in data["rules"]]
    new_id = str(uuid.uuid4())[:8]

    new_rule = {
        "id": new_id,
        "type": rule_type,
        "score": score,
        "patterns": [pattern]
    }
    data["rules"].append(new_rule)
    save_rules(data)
    print(f"Added rule {new_id}")

def update_rule(rule_id, pattern=None, score=None):
    data = load_rules()
    for rule in data["rules"]:
        if rule["id"] == rule_id:
            if pattern and pattern not in rule["patterns"]:
                rule["patterns"].append(pattern)
            if score:
                rule["score"] = score
            save_rules(data)
            print(f"Updated rule {rule_id}")
            return
    print(f"Rule {rule_id} not found")

def delete_rule(rule_id):
    data = load_rules()
    before = len(data["rules"])
    data["rules"] = [r for r in data["rules"] if r["id"] != rule_id]

    if len(data["rules"]) == before:
        print("Rule not found")
    else:
        print("Deleted")
    save_rules(data)
    print(f"Deleted rule {rule_id}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WAF Rules CLI")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("list", help="List all rules")

    add_parser = subparsers.add_parser("add", help="Add a new rule")
    add_parser.add_argument("--type", required=True)
    add_parser.add_argument("--pattern", required=True)
    add_parser.add_argument("--score", type=int, default=10)

    update_parser = subparsers.add_parser("update", help="Update a rule")
    update_parser.add_argument("--id", required=True)
    update_parser.add_argument("--pattern")
    update_parser.add_argument("--score", type=int)

    delete_parser = subparsers.add_parser("delete", help="Delete a rule")
    delete_parser.add_argument("--id", required=True)

    args = parser.parse_args()

    if args.command == "list":
        list_rules()
    elif args.command == "add":
        add_rule(args.type, args.pattern, args.score)
    elif args.command == "update":
        update_rule(args.id, args.pattern, args.score)
    elif args.command == "delete":
        delete_rule(args.id)