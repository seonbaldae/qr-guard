"""Bounded local report receipts, with the same lifetime as the scan store.

Counts describe reports accepted by this server process, not a global reputation
database. A receipt belongs to a scan, not an authenticated person's identity.
Only the URL already retained by the server is used as an aggregation key.
"""

from app.models import ReportReceipt, ScanReport
from app.precheck.payload import normalize


class ReportStore:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}
        self.submitted_scans: set[str] = set()

    def receipt(self, report: ScanReport) -> ReportReceipt:
        count = self.counts.get(normalize(report.requested_url), 0)
        return ReportReceipt(
            scan_id=report.scan_id, report_count=count, is_reported=count > 0,
            reported_by_user=report.scan_id in self.submitted_scans,
        )

    def accept(self, report: ScanReport) -> ReportReceipt:
        # This synchronous operation has no await between checking and recording,
        # so repeated requests cannot increment twice on the single API worker.
        if report.scan_id not in self.submitted_scans:
            key = normalize(report.requested_url)
            self.counts[key] = self.counts.get(key, 0) + 1
            self.submitted_scans.add(report.scan_id)
        return self.receipt(report)

    def decorate(self, report: ScanReport) -> ScanReport:
        receipt = self.receipt(report)
        return report.model_copy(update={
            "report_count": receipt.report_count,
            "is_reported": receipt.is_reported,
            "reported_by_user": receipt.reported_by_user,
        })
