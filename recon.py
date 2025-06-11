import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import track
from rich.prompt import Prompt
from rich.panel import Panel
import json
import os

console = Console()
visited = set()

SIGNATURES = {
    "wp-content": "WordPress",
    "content=\"Joomla!": "Joomla",
    "core/misc/drupal.js": "Drupal",
    "skin/frontend": "Magento",
    "jquery": "jQuery",
}

CVE_HINTS = {
    "WordPress": "https://www.cvedetails.com/vulnerability-list/vendor_id-2337/product_id-4096/Wordpress-Wordpress.html",
    "Joomla": "https://www.cvedetails.com/vulnerability-list/vendor_id-653/product_id-11007/Joomla-Joomla.html",
    "Drupal": "https://www.cvedetails.com/vulnerability-list/vendor_id-136/product_id-1556/Drupal-Drupal.html",
    "Magento": "https://www.cvedetails.com/vulnerability-list/vendor_id-12540/Magento.html",
    "jQuery": "https://www.cvedetails.com/vulnerability-list/vendor_id-6538/Jquery.html",
}

from rich.box import ROUNDED

def print_banner():
    ascii_logo = """
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗ 
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══██╗██╔══██║██╔═══╝    ██║   ██║   ██║██╔══██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║  ██║██║  ██║██║        ██║   ╚██████╔╝██║  ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝

[bold white]Developed by Zahir Lehri | LogicX Technologies[/bold white]
[green]Website Fingerprinting & CVE-Based Vulnerability Scanner[/green]
"""
    logo_panel = Panel(
        ascii_logo,
        style="bold red",
        expand=False,
        border_style="bright_red",
        box=ROUNDED
    )

    console.print(logo_panel, justify="center")

def crawl_site(base_url, max_pages=20):
    to_visit = [base_url]
    discovered_pages = []

    console.rule("[bold green]Website Crawling")
    console.print(f"[bold cyan]Target:[/bold cyan] {base_url}")

    while to_visit and len(discovered_pages) < max_pages:
        url = to_visit.pop()
        if url in visited:
            continue
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            discovered_pages.append((url, response.text))
            visited.add(url)

            for link in soup.find_all("a", href=True):
                full_url = urljoin(url, link["href"])
                if base_url in full_url and full_url not in visited:
                    to_visit.append(full_url)

            console.print(f"[green]✓ Crawled:[/green] {url}")

        except Exception as e:
            console.print(f"[red]✗ Error:[/red] {url} → {e}")

    console.print(f"\n[bold green]✔ Completed:[/bold green] {len(discovered_pages)} pages discovered.\n")
    return discovered_pages

def detect_technologies(html_pages):
    found_tech = set()
    console.rule("[bold green]Technology Detection")

    for url, html in track(html_pages, description="Scanning pages..."):
        for pattern, tech in SIGNATURES.items():
            if pattern.lower() in html.lower():
                found_tech.add(tech)

    if found_tech:
        table = Table(title="Detected Technologies")
        table.add_column("Technology", style="cyan")
        table.add_column("CVE Reference", style="yellow")
        for tech in found_tech:
            table.add_row(tech, CVE_HINTS.get(tech, "N/A"))
        console.print(table)
    else:
        console.print("[yellow]No recognizable technologies detected.[/yellow]")

    return found_tech

def inject_param(url, payload):
    if "?" not in url:
        return f"{url}?vuln={payload}"
    return url + f"&vuln={payload}"

def scan_vulnerabilities(base_url, discovered_pages):
    console.rule("[bold red]Vulnerability Scan")
    vulnerabilities = {
        "XSS": [],
        "SQL Injection": [],
        "Clickjacking": False,
        "Security Headers": {},
        "Open Redirects": [],
        "Exposed Admin Panels": []
    }

    test_params = {
        "xss": "<script>alert(1)</script>",
        "sqli": "' OR '1'='1"
    }

    for url, _ in track(discovered_pages, description="Scanning for vulns..."):
        try:
            xss_url = inject_param(url, test_params["xss"])
            sqli_url = inject_param(url, test_params["sqli"])

            xss_response = requests.get(xss_url, timeout=5)
            sqli_response = requests.get(sqli_url, timeout=5)

            if test_params["xss"] in xss_response.text:
                vulnerabilities["XSS"].append(xss_url)

            if "sql" in sqli_response.text.lower() or "syntax" in sqli_response.text.lower():
                vulnerabilities["SQL Injection"].append(sqli_url)

            if any(k in url.lower() for k in ["redirect", "url="]):
                redirect_test_url = inject_param(url, "http://evil.com")
                response = requests.get(redirect_test_url, allow_redirects=False)
                if "evil.com" in response.headers.get("Location", ""):
                    vulnerabilities["Open Redirects"].append(redirect_test_url)

            if any(k in url.lower() for k in ["admin", "login", "dashboard"]):
                vulnerabilities["Exposed Admin Panels"].append(url)

            response = requests.get(url, timeout=5)
            headers = response.headers
            for header in ["X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy", "Strict-Transport-Security"]:
                if header not in headers:
                    vulnerabilities["Security Headers"][header] = "Missing"

            if "X-Frame-Options" not in headers:
                vulnerabilities["Clickjacking"] = True

        except Exception as e:
            console.print(f"[red]Error scanning {url}:[/red] {e}")

    # Display results
    if vulnerabilities["XSS"]:
        console.print("[bold yellow]Potential XSS:[/bold yellow]")
        for xss in vulnerabilities["XSS"]:
            console.print(f"[red]•[/red] {xss}")
    if vulnerabilities["SQL Injection"]:
        console.print("[bold yellow]Potential SQL Injection:[/bold yellow]")
        for sqli in vulnerabilities["SQL Injection"]:
            console.print(f"[red]•[/red] {sqli}")
    if vulnerabilities["Open Redirects"]:
        console.print("[bold red]Open Redirects Detected:[/bold red]")
        for r in vulnerabilities["Open Redirects"]:
            console.print(f"[red]•[/red] {r}")
    if vulnerabilities["Clickjacking"]:
        console.print("[bold red]Clickjacking possible! Missing X-Frame-Options header[/bold red]")
    if vulnerabilities["Security Headers"]:
        console.print("[bold cyan]Missing Security Headers:[/bold cyan]")
        for header, status in vulnerabilities["Security Headers"].items():
            console.print(f"[magenta]• {header}[/magenta]: {status}")
    if vulnerabilities["Exposed Admin Panels"]:
        console.print("[bold cyan]Exposed Admin/Login Pages:[/bold cyan]")
        for a in vulnerabilities["Exposed Admin Panels"]:
            console.print(f"[blue]•[/blue] {a}")

    return vulnerabilities

def export_results(domain, pages, technologies, vulnerabilities=None):
    safe_domain = domain.replace("https://", "").replace("http://", "").replace("/", "_")
    os.makedirs("scan_results", exist_ok=True)

    txt_path = f"scan_results/{safe_domain}_scan.txt"
    json_path = f"scan_results/{safe_domain}_scan.json"

    with open(txt_path, "w", encoding="utf-8") as f_txt, open(json_path, "w", encoding="utf-8") as f_json:
        f_txt.write("Website Scan Report\n")
        f_txt.write(f"Target: {domain}\n\nDiscovered Pages:\n")
        for url, _ in pages:
            f_txt.write(f"- {url}\n")
        f_txt.write("\nDetected Technologies and CVE Links:\n")
        for tech in technologies:
            cve = CVE_HINTS.get(tech, "N/A")
            f_txt.write(f"- {tech}: {cve}\n")

        if vulnerabilities:
            f_txt.write("\nVulnerability Report:\n")
            for key, value in vulnerabilities.items():
                if isinstance(value, list):
                    for v in value:
                        f_txt.write(f"- {key}: {v}\n")
                elif isinstance(value, dict):
                    for h, s in value.items():
                        f_txt.write(f"- {key} -> {h}: {s}\n")
                else:
                    f_txt.write(f"- {key}: {value}\n")

        json.dump({
            "target": domain,
            "pages": [url for url, _ in pages],
            "technologies": {tech: CVE_HINTS.get(tech, "N/A") for tech in technologies},
            "vulnerabilities": vulnerabilities
        }, f_json, indent=2)

    console.print(f"\n[bold green]✓ Exported Results:[/bold green]")
    console.print(f"[cyan]• Text file:[/cyan] {txt_path}")
    console.print(f"[cyan]• JSON file:[/cyan] {json_path}")

def main():
    print_banner()
    console.rule("[bold blue]Website CVE & Vulnerability Scanner")
    target = Prompt.ask("Enter the website URL (e.g., https://example.com)")
    if not target.startswith("http"):
        target = "http://" + target

    pages = crawl_site(target)
    techs = detect_technologies(pages)
    vulns = scan_vulnerabilities(target, pages)
    export_results(target, pages, techs, vulns)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan cancelled by user.[/bold red]")
