import requests
from hashlib import sha256
from typing import Tuple

API_KEY = "bb8de54a69048b6a88349f0c41ecd4fe6fbf509525dbd79b7b98e1b69a0e00fc"


class VirusTotalScanner:
    def __init__(self):
        self.api_key = API_KEY
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

        except Exception:
            return 0, 0
