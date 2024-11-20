import requests
from hashlib import sha256
from typing import Tuple


class VirusTotalScanner:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"

    def get_av_reports(self, binary_path: str) -> Tuple[int, int]:
        """
        get antivirus scan reports from VirusTotal for a given binary file.

        args:
        + binary_path: path to the binary file to scan

        returns:
        + tuple containing (total_scans, positive_detections)
        """
        try:
            with open(binary_path, "rb") as binary:
                file_content = binary.read()
                file_hash = sha256(file_content).hexdigest()

            url = f"{self.base_url}/files/{file_hash}"
            headers = {"accept": "application/json", "x-apikey": self.api_key}

            response = requests.get(url, headers=headers)
            data = response.json()

            stats = data["data"]["attributes"]["last_analysis_stats"]

            total = sum(
                [
                    stats["malicious"],
                    stats["suspicious"],
                    stats["undetected"],
                    stats["harmless"],
                ]
            )

            positives = stats["malicious"]

            return total, positives

        except Exception as e:
            raise Exception(f"Error getting AV reports: {str(e)}")


@staticmethod
def getAVReports(binary_path: str) -> Tuple:
    API_KEY = "YOUR-API-KEY-HERE"
    scanner = VirusTotalScanner(API_KEY)
    total, positives = scanner.get_av_reports(binary_path)
    return total, positives
