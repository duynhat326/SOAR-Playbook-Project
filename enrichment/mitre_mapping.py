"""
enrichment/mitre_mapping.py
===========================
MITRE ATT&CK Technique Mapping Engine.

Chức năng:
  - Đọc bảng pattern từ data/mitre_technique_map.json
  - Khớp process_name và command_line của alert với các pattern
  - Trả về danh sách MITREMapping (technique ID, tactic, confidence...)

Thuật toán matching:
  - "exact"    : so sánh chính xác sau khi lowercase + strip
  - "contains" : kiểm tra substring (case-insensitive)

Thiết kế:
  - Class MITREMapper là stateless sau khi load DB
  - Trả về list để 1 alert có thể map sang nhiều technique (đúng thực tế)
  - Kèm theo list "dangerous_processes" từ DB để policy engine dùng
"""

import json
from pathlib import Path
from typing import List, Optional

from loguru import logger

from schemas.alert import MalwareAlert, MITREMapping


_DB_PATH = Path(__file__).parent.parent / "data" / "mitre_technique_map.json"


class MITREMapper:
    """
    Engine mapping alert indicators → MITRE ATT&CK techniques.

    Load toàn bộ mapping rules từ JSON DB vào memory khi khởi tạo,
    sau đó dùng pattern matching để tìm technique phù hợp.
    """

    def __init__(self, db_path: Optional[Path] = None):
        self._db_path = db_path or _DB_PATH
        db = self._load_db()
        self._process_patterns: List[dict] = db.get("process_patterns", [])
        self._command_patterns: List[dict] = db.get("command_line_patterns", [])
        self._dangerous_processes: List[str] = [
            p.lower() for p in db.get("dangerous_processes", [])
        ]
        logger.debug(
            f"[MITRE] Loaded {len(self._process_patterns)} process patterns, "
            f"{len(self._command_patterns)} command patterns, "
            f"{len(self._dangerous_processes)} dangerous processes"
        )

    def _load_db(self) -> dict:
        """Load mapping DB từ JSON file."""
        try:
            with open(self._db_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"[MITRE] DB not found: {self._db_path}")
            return {}
        except json.JSONDecodeError as e:
            logger.error(f"[MITRE] JSON parse error: {e}")
            return {}

    # ──────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────

    def map_alert(self, alert: MalwareAlert) -> List[MITREMapping]:
        """
        Thực hiện mapping toàn diện cho 1 alert.

        Kiểm tra cả process_name lẫn command_line.
        Loại bỏ duplicate technique (cùng technique_id) — giữ cái có
        confidence cao nhất.

        Args:
            alert: Alert cần mapping

        Returns:
            List[MITREMapping] — có thể rỗng nếu không match pattern nào
        """
        logger.debug(
            f"[MITRE] Mapping alert | process='{alert.process_name}' | "
            f"cmdline='{alert.command_line[:60]}...'"
        )

        findings: List[MITREMapping] = []

        # Match process_name
        findings.extend(
            self._match_process(alert.process_name)
        )

        # Match command_line
        findings.extend(
            self._match_command(alert.command_line)
        )

        # Deduplicate: giữ technique có confidence cao nhất nếu trùng ID
        deduped = self._deduplicate(findings)

        if deduped:
            techniques_str = ", ".join(
                f"{m.technique_id}({m.tactic})" for m in deduped
            )
            logger.debug(f"[MITRE] Matched {len(deduped)} technique(s): {techniques_str}")
        else:
            logger.debug("[MITRE] No technique matched")

        return deduped

    def is_dangerous_process(self, process_name: str) -> bool:
        """
        Kiểm tra xem process có nằm trong blacklist nguy hiểm không.

        Dùng bởi policy engine để trigger kill_process action.

        Args:
            process_name: Tên tiến trình (case-insensitive)

        Returns:
            True nếu process nằm trong dangerous_processes list
        """
        return process_name.lower().strip() in self._dangerous_processes

    def get_highest_severity_weight(self, mappings: List[MITREMapping]) -> float:
        """
        Lấy severity_weight cao nhất từ danh sách technique mappings.
        Dùng để đóng góp vào risk score calculation.

        Returns:
            float trong [0.0, 1.0], hoặc 0.0 nếu list rỗng
        """
        if not mappings:
            return 0.0
        # confidence trong MITREMapping được set = severity_weight khi tạo
        return max(m.confidence for m in mappings)

    # ──────────────────────────────────────────────
    # Private helpers
    # ──────────────────────────────────────────────

    def _match_process(self, process_name: str) -> List[MITREMapping]:
        """So khớp process_name với các process pattern trong DB."""
        results = []
        normalized = process_name.lower().strip()

        for rule in self._process_patterns:
            pattern = rule["pattern"].lower()
            match_type = rule.get("match_type", "contains")

            matched = False
            if match_type == "exact":
                matched = (normalized == pattern)
            elif match_type == "contains":
                matched = (pattern in normalized)

            if matched:
                results.append(MITREMapping(
                    technique_id=rule["technique_id"],
                    technique_name=rule["technique_name"],
                    tactic=rule["tactic"],
                    matched_pattern=f"process:{rule['pattern']}",
                    confidence=rule.get("severity_weight", 0.5),
                ))

        return results

    def _match_command(self, command_line: str) -> List[MITREMapping]:
        """So khớp command_line với các command pattern trong DB."""
        results = []
        normalized = command_line.lower()

        for rule in self._command_patterns:
            pattern = rule["pattern"].lower()
            match_type = rule.get("match_type", "contains")

            matched = False
            if match_type == "exact":
                matched = (normalized == pattern)
            elif match_type == "contains":
                matched = (pattern in normalized)

            if matched:
                results.append(MITREMapping(
                    technique_id=rule["technique_id"],
                    technique_name=rule["technique_name"],
                    tactic=rule["tactic"],
                    matched_pattern=f"cmdline:{rule['pattern']}",
                    confidence=rule.get("severity_weight", 0.5),
                ))

        return results

    def _deduplicate(self, mappings: List[MITREMapping]) -> List[MITREMapping]:
        """
        Loại bỏ duplicate technique_id — giữ cái có confidence cao nhất.

        Ví dụ: T1059.001 được match bởi cả '-enc' và 'IEX' trong command_line
        → chỉ giữ 1, với confidence = max(0.8, 0.85) = 0.85
        """
        best: dict[str, MITREMapping] = {}
        for m in mappings:
            existing = best.get(m.technique_id)
            if existing is None or m.confidence > existing.confidence:
                best[m.technique_id] = m
        # Sắp xếp theo confidence giảm dần để dễ đọc
        return sorted(best.values(), key=lambda x: x.confidence, reverse=True)
