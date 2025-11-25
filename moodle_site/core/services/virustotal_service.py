"""
VirusTotal API integration service.

Handles file scanning and report retrieval from VirusTotal.
"""
import time
from typing import Dict, Tuple, Optional
import requests
from django.conf import settings


class VirusTotalError(Exception):
    """Custom exception for VirusTotal API errors."""
    pass


class VirusTotalService:
    """
    Service for interacting with VirusTotal API v3.

    Handles file uploads, scanning, and report retrieval.
    """

    def __init__(self):
        self.api_key = settings.VIRUSTOTAL_API_KEY
        self.api_url = settings.VIRUSTOTAL_API_URL
        self.disabled = getattr(settings, 'DISABLE_VIRUSTOTAL', False)
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

        if not self.disabled and not self.api_key:
            raise VirusTotalError(
                "VIRUSTOTAL_API_KEY not configured in settings"
            )

    def scan_file(
        self,
        file_bytes: bytes,
        filename: str,
        timeout: int = 300
    ) -> Tuple[bool, Dict, str]:
        """
        Scan a file with VirusTotal.

        Args:
            file_bytes: Binary content of the file
            filename: Name of the file
            timeout: Maximum time to wait for scan results in seconds

        Returns:
            Tuple of (is_malicious, summary_dict, report_id)

        Raises:
            VirusTotalError: If the API request fails or times out
        """
        # Bypass mode for testing
        if self.disabled:
            return False, {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 1,
                "undetected": 0,
                "timeout": 0,
                "status": "completed",
                "analysis_date": 0,
                "bypass": True,
            }, "bypass-mode-no-scan"

        try:
            # Upload file for scanning
            upload_url = f"{self.api_url}files"
            files = {"file": (filename, file_bytes)}

            response = requests.post(
                upload_url,
                headers=self.headers,
                files=files,
                timeout=60
            )

            if response.status_code == 401:
                raise VirusTotalError(
                    "Invalid VirusTotal API key. Please check your configuration."
                )
            elif response.status_code == 413:
                raise VirusTotalError(
                    "File too large for VirusTotal API (max 32MB for free tier)."
                )
            elif response.status_code != 200:
                raise VirusTotalError(
                    f"VirusTotal upload failed: {response.status_code} - {response.text}"
                )

            upload_data = response.json()
            analysis_id = upload_data.get("data", {}).get("id")

            if not analysis_id:
                raise VirusTotalError("No analysis ID returned from VirusTotal")

            # Poll for results
            is_malicious, summary = self._wait_for_analysis(
                analysis_id, timeout=timeout
            )

            return is_malicious, summary, analysis_id

        except requests.exceptions.Timeout:
            raise VirusTotalError(
                "VirusTotal API request timed out. Please try again."
            )
        except requests.exceptions.ConnectionError:
            raise VirusTotalError(
                "Could not connect to VirusTotal. Please check your internet connection."
            )
        except requests.exceptions.RequestException as e:
            raise VirusTotalError(f"VirusTotal API error: {str(e)}")

    def _wait_for_analysis(
        self,
        analysis_id: str,
        timeout: int = 300,
        poll_interval: int = 10
    ) -> Tuple[bool, Dict]:
        """
        Wait for VirusTotal analysis to complete.

        Args:
            analysis_id: The analysis ID to check
            timeout: Maximum time to wait in seconds
            poll_interval: Time between polls in seconds

        Returns:
            Tuple of (is_malicious, summary_dict)

        Raises:
            VirusTotalError: If analysis times out or fails
        """
        analysis_url = f"{self.api_url}analyses/{analysis_id}"
        start_time = time.time()

        while True:
            if time.time() - start_time > timeout:
                raise VirusTotalError(
                    "VirusTotal analysis timed out waiting for results"
                )

            response = requests.get(
                analysis_url,
                headers=self.headers,
                timeout=30
            )

            if response.status_code != 200:
                raise VirusTotalError(
                    f"Failed to get analysis results: {response.status_code}"
                )

            data = response.json()
            status = data.get("data", {}).get("attributes", {}).get("status")

            if status == "completed":
                # Extract results
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("stats", {})

                is_malicious = stats.get("malicious", 0) > 0

                summary = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "timeout": stats.get("timeout", 0),
                    "status": status,
                    "analysis_date": attributes.get("date", 0),
                }

                return is_malicious, summary

            # Still queued or in progress
            time.sleep(poll_interval)

    def get_file_report(self, file_hash: str) -> Optional[Dict]:
        """
        Get existing VirusTotal report for a file by hash.

        Args:
            file_hash: SHA-256 hash of the file

        Returns:
            Report dict if found, None otherwise

        Raises:
            VirusTotalError: If the API request fails
        """
        try:
            url = f"{self.api_url}files/{file_hash}"

            response = requests.get(
                url,
                headers=self.headers,
                timeout=30
            )

            if response.status_code == 404:
                return None
            elif response.status_code != 200:
                raise VirusTotalError(
                    f"Failed to get file report: {response.status_code}"
                )

            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "sha256": attributes.get("sha256"),
                "analysis_date": attributes.get("last_analysis_date", 0),
            }

        except requests.exceptions.RequestException as e:
            raise VirusTotalError(f"VirusTotal API error: {str(e)}")


# Singleton instance
_vt_service: Optional[VirusTotalService] = None


def get_virustotal_service() -> VirusTotalService:
    """Get or create VirusTotal service instance."""
    global _vt_service
    if _vt_service is None:
        _vt_service = VirusTotalService()
    return _vt_service
