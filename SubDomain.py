import argparse
import json
import requests
from BruteForceSubDomain import BruteForceSubDomain


class SubDomain:

    def __init__(self, domain, apikey, nameserver="8.8.8.8"):

        self.domain = domain
        self.nameserver = nameserver
        self.threatCrowdUrl = "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={}".format(
            domain)
        self.certificateTransperencyUrl = "https://certspotter.com/api/v0/certs?domain={}".format(
            domain)
        self.certificateTransperencyUrl1 = "https://ctsearch.entrust.com/api/v1/certificates\
        ?fields=issuerCN,subjectO,issuerDN,issuerO,subjectDN,signAlg,san,\publicKeyType,publicKeySize\
        ,validFrom,validTo,sn,ev,logEntries.logName,subjectCNReversed,cert&domain={}&includeExpired=\
        false&exactMatch=false&limit=5000".format(domain)
        self.virusTotalUrl = "https://www.virustotal.com/vtapi/v2/domain/report?apikey={0}&domain={1}".format(
            apikey, domain)
        self.certificateTransperencyUrl2 = "https://crt.sh/?q=%25.{0}&output=json".format(
            domain)
        self.hackerTargetUrl = "https://api.hackertarget.com/hostsearch/?q={0}".format(
            domain)

    def send_threat_crowd_request(self):

        response = requests.get(self.threatCrowdUrl)
        try:
            return set(response.json()['subdomains'])
        except:
            return set()

    def send_certificate_transperency_request_other(self):

        subdomain_data = []
        response = requests.get(self.certificateTransperencyUrl1)
        try:
            response.json()
        except:
            return set()
        for i in range(0, len(response.json())):
            try:
                data = str(response.json()[i]['subjectDN']).split("=")[1]
                subdomain_data.append(data.split(",")[0])
            except:
                continue
        return set(subdomain_data)

    def send_certificate_transperency_request(self):

        subdomain_data = []
        response = requests.get(self.certificateTransperencyUrl)
        for i in range(0, len(response.json())):
            try:
                subdomain_data += response.json()[i]['dns_names']
            except:
                continue
        return set(subdomain_data)

    def virusTotalRequest(self):

        response = requests.get(self.virusTotalUrl)
        try:
            return set(response.json()['subdomains'])
        except:
            return set()

    def send_certificate_transperency_request_cert_sh(self):

        data_set = set()
        resp = requests.get(self.certificateTransperencyUrl2)
        if resp.status_code != 200:
            return
        fixed_raw = '[%s]' % str(resp.text).replace('}{', '},{')
        for cert in json.loads(fixed_raw):
            data_set.update([cert.get('name_value')])
        return data_set

    def send_hacker_target(self):

        data_set = set()
        resp = requests.get(self.hackerTargetUrl)
        if resp.status_code != 200:
            return
        if resp.text == '':
            return
        if resp.text.startswith('error'):
            return
        for line in resp.text.split("\n"):
            line = line.strip()
            if line == '':
                continue
            host, _ = line.split(",")
            data_set.update([host])
        return data_set


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--Brute", type=str,
                        help="Brute Force Domains with List- Y")
    parser.add_argument("--Api", type=str, help="Enter Virustotal API Key")
    parser.add_argument("--Domain", type=str, help="Enter a Domain/Domains in seperated by -.\
     For Ex. yahoo.com-google.com or yahoo.com")
    args = parser.parse_args()
    if args.Api and args.Domain:
        virusTotalApiKey = args.Api
        Domain = str(args.Domain).split(":")
        print(Domain)
        for d in Domain:
            c = SubDomain(d, virusTotalApiKey)
            print("*****************Found Through ThreatCrowd*****************")
            print()
            print(c.send_threat_crowd_request())
            print()
            print(
                "*****************Certificate Transperency Logs*****************")
            print()
            print(c.send_certificate_transperency_request())
            print()
            print(
                "*****************Certificate Transperency Logs Other*****************")
            print()
            print(c.send_certificate_transperency_request_other())
            print()
            print(
                "*****************Certificate Transperency Logs CertSh*****************")
            print()
            print(c.send_certificate_transperency_request_cert_sh())
            print()
            print("*****************Found Through VirusTotal*****************")
            print()
            print(c.virusTotalRequest())
            print()
            print("*****************Hacker target*****************")
            print()
            print(c.send_hacker_target())
            print()
            print("*****************DeDuped Data*****************")
            print()
            print(c.send_hacker_target().union(c.send_threat_crowd_request()).union(
                c.send_certificate_transperency_request()).union(
                c.send_certificate_transperency_request_other()).union(
                c.send_certificate_transperency_request_cert_sh()).union(
                c.virusTotalRequest()))
            print()
            if args.Brute == "Y":
                print("*****************CBruteForcer*****************")
                print()
                b = BruteForceSubDomain(d)
                b.dns_brute_force()
                print()
        return
    elif args.Domain:
        Domain = str(args.Domain).split(":")
        for d in Domain:
            print(d)
            c = SubDomain(d, None)
            print("*****************Found Through ThreatCrowd*****************")
            print()
            print(c.send_threat_crowd_request())
            print()
            print(
                "*****************Certificate Transperency Logs*****************")
            print()
            print(c.send_certificate_transperency_request())
            print()
            print(
                "*****************Certificate Transperency Logs Other*****************")
            print()
            print(c.send_certificate_transperency_request_other())
            print()
            print(
                "*****************Certificate Transperency Logs CertSh*****************")
            print()
            print(c.send_certificate_transperency_request_cert_sh())
            print()
            print("*****************Hacker target*****************")
            print()
            print(c.send_hacker_target())
            print()
            print("*****************DeDuped Data*****************")
            print()
            print(c.send_hacker_target().union(c.send_threat_crowd_request()).union(
                c.send_certificate_transperency_request()).union(
                c.send_certificate_transperency_request_other()).union(
                c.send_certificate_transperency_request_cert_sh()))
            print()
            if args.Brute == "Y":
                print("*****************CBruteForcer*****************")
                print()
                b = BruteForceSubDomain(d)
                b.dns_brute_force()
                print()
        return


if __name__ == '__main__':
    main()
