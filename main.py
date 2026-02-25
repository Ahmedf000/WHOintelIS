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


def design_table(lookup_results):

    if not lookup_results:
        print("No results to be displayed")
        return

    console = Console()
    table = Table(show_header=True, header_style="bold blue", title_style="WHOintellIS results")
    table.add_column("WHOIS_Lookup", style="green")
    table.add_column("ASN_Lookup", style="cyan")
    table.add_column("GEOLOCATION_lookup", style="yellow")


    console.print(table)


def domain_solve(ip_address):
    """This solve by socket will work for WHOIS as it requires a domain"""
    resolver = socket.gethostbyname(ip_address)
    return resolver



def whois_lookup(domain):
    get_domain = domain_solve(domain)

    try:
        who_lookup = whois.whois(domain)
        lookup_Info = {
            'Domain_Name': who_lookup.domain_name,
            'Registrar_Info': who_lookup.registrar,
            'Creation_Date':who_lookup.creation_date[0],
            'Expiration_Date': who_lookup.expiration_date[0],
        }

        return lookup_Info

    except Exception as e:
        return f"Could not Complete the Lookup: {str(e)}"




def ASN_lookup(ip_address):

    obj = IPWhois(ip_address)
    results = obj.lookup_rdap()

    try:
        asn_lookup = {
            'Autonomous_System Number': results['asn'],
            'ASN Network': {
                'ANS Cidr':results['asn_cidr'],
                'Network Status': results['network']['status'],
                'Start Address': results['network']['start_address'],
                'End Address': results['network']['end_address'],
                'Name': results['network']['name'],
                'Kind': results['network']['contact']['kind'],
            },
            'Description': results['asn_description'],
            'Modifications': {
                'Last Changed': results['network']['events']['timestamp'],
            }
        }

    except Exception as e:
        return f"Could not Complete the ASN Lookup: {str(e)}"

    return asn_lookup




def geolocation_finding(ip_address):

    import json

    url1 = f'https://ip-api.com/{ip_address}'
    try:
        geo_request = requests.get(url1)
        response = geo_request.json()
        js = json.dumps(response, indent=4)

        if geo_request.status_code == 404 and geo_request.status_code == 403:
            return f"Could not get a response back due to an Error"
        if geo_request.status_code == 500:
            return f"Could not get a response back due to an Server Error"

    except Exception as e:
        return f"Could not Complete the Geolocation Finding: {str(e)}"
    except requests.exceptions.RequestException as e:
        return f"Could not form successful request: {str(e)}"

    return js




def main():
    parser = argparse.ArgumentParser(description="Domain - IP address Lookup Tool")
    parser.add_argument("-w","--whois", help="Domain to search")
    parser.add_argument("-a","--asn_lookup", help="ASN to search")
    parser.add_argument("-g","--geolocation", help="Geolocation to search")
    args = parser.parse_args()

    import sys
    if len(sys.argv) < 1:
        print(f"Please use main.py -h")
        sys.exit(1)

    extension = ['com','net','org']
    for ext in extension:
        if ext in args.whois:
            clean_domain = []
            split_prefix = args.whois.split('.')
            clean_domain.append(split_prefix[1])
            clean_domain.append(split_prefix[2])
            get_correct = '.'.join(clean_domain)

            whois_lookups = whois_lookup(get_correct)
        else:
            ip_to_domain = domain_solve(args.whois)
            whois_lookups = whois_lookup(ip_to_domain)


    if args.asn_lookup:
        asn_search = ASN_lookup(args.asn_lookup)


    if args.geolocation:
        location_lookup = geolocation_finding(args.geolocation)



if __name__ == "__main__":
    main()
