import os
import requests
from hashlib import sha256
from typing import Tuple
from dotenv import load_dotenv

load_dotenv()


class VirusTotalScanner:
    def __init__(self):
        self.api_key = os.getenv("VT_API_KEY")
        if not self.api_key:
            print(f"VT_API_KEY environment variable not set")
        self.base_url = "https://www.virustotal.com/api/v3"

    def get_av_reports(self, binary_path: str) -> Tuple[int, int]:
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
