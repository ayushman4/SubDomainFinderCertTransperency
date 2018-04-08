import os
import dnslib
from concurrent.futures import ThreadPoolExecutor


class BruteForceSubDomain:

    def __init__(self, domain, nameserver="8.8.8.8"):

        self.name_server = nameserver
        self.domain = domain

    def __fire_in_the_hole(self, prefix):

        domain = prefix + "." + self.domain
        query = dnslib.DNSRecord.question(domain, "A")
        response = query.send(self.name_server, 53)
        response = dnslib.DNSRecord.parse(response)
        response = response.rr
        if len(response) > 0 and response[0].rdata:
            print(domain)
        return

    def __create_dns_records(self):

        if os.path.isfile("namelist.txt"):
            with open("namelist.txt", "r") as file:
                return file.read().split("\n")

    def dns_brute_force(self):

        prefix_data = self.__create_dns_records()
        with ThreadPoolExecutor(max_workers=64) as executor:
            executor.map(self.__fire_in_the_hole, prefix_data)
        executor.shutdown()
