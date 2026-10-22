#!/usr/bin/env python3
"""Render report.html from results.json using the Jinja2 template."""

import json
from datetime import datetime
from jinja2 import Environment, FileSystemLoader


def main():
    # Read the scan results
    with open("results.json") as f:
        results = json.load(f)

    hosts = results["hosts"]
    
    # Calculate summary numbers
    port_count = sum(len(h["ports"]) for h in hosts)
    risk_count = sum(1 for h in hosts for p in h["ports"] if p["risk_label"])

    # Set up Jinja2 to look in the 'templates' folder
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("report_template.html")

    # Fill the template with data
    html = template.render(
        target=results["target"],
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
        hosts=hosts,
        host_count=len(hosts),
        port_count=port_count,
        risk_count=risk_count,
    )

    # Write the output file
    with open("report.html", "w") as f:
        f.write(html)

    print("[+] report.html written successfully!")


if __name__ == "__main__":
    main()