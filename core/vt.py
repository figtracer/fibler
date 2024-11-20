from __future__ import print_function
import json
import hashlib
from virus_total_apis import PublicApi as VirusTotalPublicApi

API_KEY = "PUT YOUR API KEY HERE"


@staticmethod
def getAVReports(binary: str) -> int:
    bin_vt = "f{binary}".encode("utf-8")
    bin_md5 = hashlib.md5(bin_vt).hexdigest()

    vt = VirusTotalPublicApi(API_KEY)

    response = vt.get_file_report(bin_md5)

    total = response.get("total")
    positives = response.get("positives")

    return total, positives
