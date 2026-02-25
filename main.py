"""
project walkthrough and pseudocode
so the climax question is "Who owns this IP/domain and Where is it"

1st: --> runs on domain
WHO is
https://www.whois.com/whois/github.com OR by using whois module (require installation)
that will return registered date - expires - latest update
registrar - org and country

2nd: --> runs on IP
ASN - autonomous system number
AS are the big networks  - Every computer or device that connects to the Internet is connected to an AS.
each AS is operated by a single large organization, such as an Internet service provider (ISP),
a large enterprise technology company, a university, or a government agency.

autonomous system number (ASN), similar to how every business has a business
license with an unique, official number.

Organization (e.g., Google) // if ASN the car you own, Then the IP block (networks prefixs) are cars you own
    └─ ASN (AS15169) ← unique ID
        ├─ IP Block 1: 8.8.8.0/24
        ├─ IP Block 2: 142.250.0.0/15
        ├─ IP Block 3: 172.217.0.0/16
        └─ (hundreds more...)


3rd: --> runs on IP
geolocation which the physical location (ciy, country, ISP)
http://ip-api.com/json/{ip} OR
- `ipinfo.io` (requires free API key)
- `ipgeolocation.io` (requires free API key)
"""

import whois
import argparse
import requests
from ipwhois import IPWhois
import time
import socket
from rich.console import Console
from rich.table import Table


def display_results(domain, ip, whois_data, asn_data, geo_data):
    console = Console()

    console.print(f"\n[bold cyan]═══════════════════════════════════════════════[/bold cyan]")
    console.print(f"[bold white]         WHOintelIS Intelligence Report[/bold white]")
    console.print(f"[bold cyan]═══════════════════════════════════════════════[/bold cyan]\n")

    if domain:
        console.print(f"[bold]Target Domain:[/bold] [cyan]{domain}[/cyan]")
    console.print(f"[bold]Resolved IP:[/bold] [green]{ip}[/green]\n")

    # WHOIS Section
    if 'error' not in whois_data:
        console.print(Panel.fit(
            f"[bold]Domain:[/bold] {whois_data['domain_name']}\n"
            f"[bold]Registrar:[/bold] {whois_data['registrar']}\n"
            f"[bold]Organization:[/bold] {whois_data['org']}\n"
            f"[bold]Country:[/bold] {whois_data['country']}\n"
            f"[bold]Created:[/bold] {whois_data['creation_date']}\n"
            f"[bold]Expires:[/bold] {whois_data['expiration_date']}",
            title="[bold magenta]WHOIS Information[/bold magenta]",
            border_style="magenta"
        ))
    else:
        console.print(f"[yellow]⚠ {whois_data['error']}[/yellow]\n")

    # ASN Section
    if 'error' not in asn_data:
        console.print(Panel.fit(
            f"[bold]ASN:[/bold] {asn_data['asn']}\n"
            f"[bold]Description:[/bold] {asn_data['asn_description']}\n"
            f"[bold]Network Name:[/bold] {asn_data['network_name']}\n"
            f"[bold]IP Block (CIDR):[/bold] {asn_data['network_cidr']}\n"
            f"[bold]Range:[/bold] {asn_data['start_address']} - {asn_data['end_address']}\n"
            f"[bold]Country:[/bold] {asn_data['country']}\n"
            f"[bold]Last Changed:[/bold] {asn_data['last_changed']}",
            title="[bold cyan]ASN Information[/bold cyan]",
            border_style="cyan"
        ))
    else:
        console.print(f"[yellow]⚠ {asn_data['error']}[/yellow]\n")

    if 'error' not in geo_data:
        console.print(Panel.fit(
            f"[bold]City:[/bold] {geo_data['city']}\n"
            f"[bold]Region:[/bold] {geo_data['region']}\n"
            f"[bold]Country:[/bold] {geo_data['country']}\n"
            f"[bold]ISP:[/bold] {geo_data['isp']}\n"
            f"[bold]Organization:[/bold] {geo_data['org']}\n"
            f"[bold]Coordinates:[/bold] {geo_data['lat']}, {geo_data['lon']}\n"
            f"[bold]Timezone:[/bold] {geo_data['timezone']}",
            title="[bold green]Geolocation[/bold green]",
            border_style="green"
        ))
    else:
        console.print(f"[yellow]⚠ {geo_data['error']}[/yellow]\n")

    console.print(f"[bold cyan]═══════════════════════════════════════════════[/bold cyan]\n")


def domain_solve(ip_address):
    """This solve by socket will work for WHOIS as it requires a domain"""
    try:
        resolver = socket.gethostbyname(ip_address)
        return resolver
    except socket.gaierror:
        return ip_address



def whois_lookup(domain):
    get_domain = domain_solve(domain)

    try:
        who_lookup = whois.whois(get_domain)

        creation = who_lookup.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        expiration = who_lookup.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]

        lookup_Info = {
                'Domain_Name': who_lookup.domain_name if who_lookup.domain_name else "N/A",
                'Registrar_Info': who_lookup.registrar if who_lookup.registrar else "N/A",
                'creation_date': str(creation) if creation else "N/A",
                'expiration_date': str(expiration) if expiration else "N/A",
                'org': who_lookup.org if who_lookup.org else "N/A",
                'country': who_lookup.country if who_lookup.country else "N/A"
            }

        return lookup_Info

    except Exception as e:
            return f"Could not Complete the Lookup: {str(e)}"




def ASN_lookup(ip_address):

    try:
        obj = IPWhois(ip_address)
        results = obj.lookup_rdap()

        last_changed = "N/A"
        if results.get('network', {}).get('events'):
            events = results['network']['events']
            if isinstance(events, list) and len(events) > 0:
                last_changed = events[0].get('timestamp', 'N/A')

        asn_lookup = {
            'asn': f"AS{results.get('asn', 'N/A')}",
            'asn_description': results.get('asn_description', 'N/A'),
            'asn_cidr': results.get('asn_cidr', 'N/A'),
            'network_cidr': results.get('network', {}).get('cidr', 'N/A'),
            'network_name': results.get('network', {}).get('name', 'N/A'),
            'start_address': results.get('network', {}).get('start_address', 'N/A'),
            'end_address': results.get('network', {}).get('end_address', 'N/A'),
            'country': results.get('asn_country_code', 'N/A'),
            'last_changed': last_changed
        }

    except Exception as e:
        return f"Could not Complete the ASN Lookup: {str(e)}"

    return asn_lookup




def geolocation_finding(ip_address):

    import json

    try:
        url = f'http://ip-api.com/json/{ip_address}'
        geo_request = requests.get(url, timeout=3)

        if geo_request.status_code == 200:
            data = geo_request.json()

            if data.get('status') == 'success':
                geo_data = {
                    'city': data.get('city', 'N/A'),
                    'region': data.get('regionName', 'N/A'),
                    'country': data.get('country', 'N/A'),
                    'isp': data.get('isp', 'N/A'),
                    'org': data.get('org', 'N/A'),
                    'lat': data.get('lat', 'N/A'),
                    'lon': data.get('lon', 'N/A'),
                    'timezone': data.get('timezone', 'N/A')
                }
                return geo_data
            else:
                return {'error': f"Geolocation failed: {data.get('message', 'Unknown error')}"}
        else:
            return {'error': f"HTTP {geo_request.status_code}"}

    except requests.RequestException as e:
        return {'error': f"Geolocation request failed: {str(e)}"}

def main():
    parser = argparse.ArgumentParser(description="Domain - IP address Lookup Tool")
    parser.add_argument("-w","--whois", help="Domain to search")
    parser.add_argument("-a","--asn_lookup", help="ASN to search")
    parser.add_argument("-g","--geolocation", help="Geolocation to search")
    args = parser.parse_args()

    target = args.target

    # Determine if input is domain or IP
    is_domain = not all(c.isdigit() or c == '.' for c in target)

    ip = domain_solve(target)

    print(f"\n[*] Gathering intelligence on: {target}")
    print(f"[*] Resolved IP: {ip}\n")

    whois_data = {}
    if is_domain:
        print("[*] Running WHOIS lookup...")
        whois_data = whois_lookup(target)
    else:
        whois_data = {'error': 'WHOIS lookup requires a domain, not an IP'}

    print("[*] Running ASN lookup...")
    asn_data = (ip)

    print("[*] Running geolocation lookup...")
    geo_data = geolocation_lookup(ip)

    # Display results
    display_results(target if is_domain else None, ip, whois_data, asn_data, geo_data)


if __name__ == "__main__":
    main()

