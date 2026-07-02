"""
engine/risk_scoring.py
======================
Risk Scoring Engine — tính điểm rủi ro tổng hợp (0–100) từ tất cả enrichment.

Công thức thiết kế:

  risk_score = (
      hash_score   * 0.30   +   # Hash reputation (quan trọng nhất)
      ip_score     * 0.25   +   # IP/C2 reputation
      asset_score  * 0.20   +   # Asset criticality
      severity_score * 0.15 +   # Severity từ EDR
      mitre_score  * 0.10        # MITRE technique severity weight
  ) * 100

Mỗi thành phần được normalize về [0.0, 1.0] trước khi nhân trọng số.

Risk Level mapping:
  0  – 25  → low
  26 – 50  → medium
  51 – 75  → high
  76 – 100 → critical

Lý do chọn trọng số này:
  - Hash reputation: direct indicator của malware, weight cao nhất
  - IP/C2: strong indicator của active C2 communication
  - Asset criticality: ảnh hưởng đến business impact
  - Severity từ EDR: signal từ detection rule, nhưng có thể false positive
  - MITRE: context thêm, không đủ mạnh để quyết định một mình
"""

from dataclasses import dataclass, field
from typing import List, Optional

from loguru import logger

from schemas.alert import (
    AssetCriticality,
    EnrichedAlert,
    HashEnrichment,
    HashReputation,
    IPEnrichment,
    IPReputation,
    MalwareAlert,
    MITREMapping,
    Severity,
)


# ──────────────────────────────────────────────
# Trọng số (weights) — điều chỉnh tại đây nếu muốn tune
# ──────────────────────────────────────────────
WEIGHT_HASH     = 0.30
WEIGHT_IP       = 0.25
WEIGHT_ASSET    = 0.20
WEIGHT_SEVERITY = 0.15
WEIGHT_MITRE    = 0.10

assert abs(WEIGHT_HASH + WEIGHT_IP + WEIGHT_ASSET + WEIGHT_SEVERITY + WEIGHT_MITRE - 1.0) < 1e-9, \
    "Tổng trọng số phải = 1.0"


@dataclass
class ScoringBreakdown:
    """
    Chi tiết điểm của từng thành phần — dùng để trace/explain trong report.

    Tất cả component_score là giá trị đã nhân trọng số (contribution).
    """
    hash_raw: float = 0.0          # Điểm hash trước khi nhân weight (0.0–1.0)
    hash_contribution: float = 0.0 # hash_raw * WEIGHT_HASH

    ip_raw: float = 0.0
    ip_contribution: float = 0.0

    asset_raw: float = 0.0
    asset_contribution: float = 0.0

    severity_raw: float = 0.0
    severity_contribution: float = 0.0

    mitre_raw: float = 0.0
    mitre_contribution: float = 0.0

    total_score: float = 0.0       # Tổng (0.0–100.0)
    risk_level: str = "unknown"

    reasoning: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "hash":     {"raw": round(self.hash_raw, 3),     "contribution": round(self.hash_contribution, 2)},
            "ip":       {"raw": round(self.ip_raw, 3),       "contribution": round(self.ip_contribution, 2)},
            "asset":    {"raw": round(self.asset_raw, 3),    "contribution": round(self.asset_contribution, 2)},
            "severity": {"raw": round(self.severity_raw, 3), "contribution": round(self.severity_contribution, 2)},
            "mitre":    {"raw": round(self.mitre_raw, 3),    "contribution": round(self.mitre_contribution, 2)},
            "total":    round(self.total_score, 1),
            "risk_level": self.risk_level,
            "reasoning": self.reasoning,
        }


class RiskScoringEngine:
    """
    Tính điểm rủi ro tổng hợp từ các enrichment results.

    Sử dụng công thức weighted sum với 5 thành phần độc lập.
    Mỗi thành phần được normalize về [0, 1] rồi nhân trọng số.
    """

    # Mapping severity → normalized score
    _SEVERITY_SCORES = {
        Severity.LOW:      0.20,
        Severity.MEDIUM:   0.45,
        Severity.HIGH:     0.75,
        Severity.CRITICAL: 1.00,
    }

    # Mapping asset criticality → normalized score
    _ASSET_SCORES = {
        AssetCriticality.LOW:      0.10,
        AssetCriticality.NORMAL:   0.45,
        AssetCriticality.CRITICAL: 1.00,
    }

    def score(self, enriched: EnrichedAlert) -> tuple[float, str, ScoringBreakdown]:
        """
        Tính risk score cho một EnrichedAlert.

        Args:
            enriched: Alert đã qua enrichment pipeline

        Returns:
            Tuple (risk_score: float, risk_level: str, breakdown: ScoringBreakdown)
            risk_score trong [0.0, 100.0]
            risk_level trong ["low", "medium", "high", "critical"]
        """
        alert = enriched.original_alert
        breakdown = ScoringBreakdown()

        logger.debug(f"[RiskScore] Calculating risk for alert: {alert.alert_id[:8]}...")

        # ── Component 1: Hash Reputation ──────────────────────────────
        hash_raw = self._score_hash(enriched.hash_enrichment, breakdown)
        breakdown.hash_raw = hash_raw
        breakdown.hash_contribution = hash_raw * WEIGHT_HASH

        # ── Component 2: IP Reputation ────────────────────────────────
        ip_raw = self._score_ip(enriched.ip_enrichment, breakdown)
        breakdown.ip_raw = ip_raw
        breakdown.ip_contribution = ip_raw * WEIGHT_IP

        # ── Component 3: Asset Criticality ────────────────────────────
        asset_raw = self._score_asset(enriched.asset_criticality, breakdown)
        breakdown.asset_raw = asset_raw
        breakdown.asset_contribution = asset_raw * WEIGHT_ASSET

        # ── Component 4: Alert Severity ───────────────────────────────
        severity_raw = self._score_severity(alert.severity, breakdown)
        breakdown.severity_raw = severity_raw
        breakdown.severity_contribution = severity_raw * WEIGHT_SEVERITY

        # ── Component 5: MITRE ATT&CK ─────────────────────────────────
        mitre_raw = self._score_mitre(enriched.mitre_mappings, breakdown)
        breakdown.mitre_raw = mitre_raw
        breakdown.mitre_contribution = mitre_raw * WEIGHT_MITRE

        # ── Tổng hợp ──────────────────────────────────────────────────
        total = (
            breakdown.hash_contribution +
            breakdown.ip_contribution +
            breakdown.asset_contribution +
            breakdown.severity_contribution +
            breakdown.mitre_contribution
        ) * 100.0

        # Clamp về [0, 100]
        total = max(0.0, min(100.0, total))

        risk_level = self._determine_level(total)
        breakdown.total_score = total
        breakdown.risk_level = risk_level

        logger.debug(
            f"[RiskScore] Score={total:.1f} ({risk_level}) | "
            f"Hash={breakdown.hash_contribution:.2f} "
            f"IP={breakdown.ip_contribution:.2f} "
            f"Asset={breakdown.asset_contribution:.2f} "
            f"Sev={breakdown.severity_contribution:.2f} "
            f"MITRE={breakdown.mitre_contribution:.2f}"
        )

        return total, risk_level, breakdown

    # ──────────────────────────────────────────────
    # Component scorers
    # ──────────────────────────────────────────────

    def _score_hash(
        self,
        hash_enrich: Optional[HashEnrichment],
        breakdown: ScoringBreakdown
    ) -> float:
        """
        Tính điểm từ hash reputation.

        Malicious: 1.0 (không cần xem xét thêm)
        Suspicious: 0.5 + bonus dựa trên tỷ lệ vendor detect
        Clean: 0.0
        Unknown: 0.15 (không biết → cần thêm context)
        """
        if hash_enrich is None:
            breakdown.reasoning.append("Hash enrichment: N/A → điểm 0")
            return 0.0

        rep = hash_enrich.reputation

        if rep == HashReputation.MALICIOUS:
            breakdown.reasoning.append(
                f"Hash MALICIOUS ({hash_enrich.malicious_vendors}/{hash_enrich.total_vendors} vendors) "
                f"→ điểm hash: 1.0"
            )
            return 1.0

        elif rep == HashReputation.SUSPICIOUS:
            # Bonus: tỷ lệ vendor detect càng cao → điểm càng cao
            ratio = (hash_enrich.malicious_vendors / hash_enrich.total_vendors
                     if hash_enrich.total_vendors > 0 else 0.0)
            score = 0.50 + ratio * 0.30   # 0.50 – 0.80
            breakdown.reasoning.append(
                f"Hash SUSPICIOUS ({hash_enrich.malicious_vendors}/{hash_enrich.total_vendors} vendors) "
                f"→ điểm hash: {score:.2f}"
            )
            return score

        elif rep == HashReputation.CLEAN:
            breakdown.reasoning.append("Hash CLEAN → điểm hash: 0.0")
            return 0.0

        else:  # UNKNOWN
            breakdown.reasoning.append(
                "Hash UNKNOWN (chưa có trong threat intel) → điểm hash: 0.15"
            )
            return 0.15

    def _score_ip(
        self,
        ip_enrich: Optional[IPEnrichment],
        breakdown: ScoringBreakdown
    ) -> float:
        """
        Tính điểm từ IP reputation.

        C2 flag là indicator mạnh nhất: +0.4 bonus nếu is_c2=True
        Confidence score (0–100) được normalize về [0, 0.6] để cộng thêm
        """
        if ip_enrich is None:
            breakdown.reasoning.append("IP enrichment: N/A → điểm 0")
            return 0.0

        rep = ip_enrich.reputation

        if rep == IPReputation.CLEAN:
            breakdown.reasoning.append(
                f"IP CLEAN ({ip_enrich.ip_address}) → điểm ip: 0.0"
            )
            return 0.0

        elif rep == IPReputation.MALICIOUS:
            # Base từ confidence score
            confidence_normalized = ip_enrich.confidence_score / 100.0
            # C2 bonus: nếu là C2 server thì thêm 0.4
            c2_bonus = 0.4 if ip_enrich.is_c2 else 0.0
            # Base score từ confidence (tối đa 0.6) + c2_bonus (tối đa 0.4) = 1.0
            score = min(1.0, confidence_normalized * 0.6 + c2_bonus)
            c2_label = " [C2 SERVER]" if ip_enrich.is_c2 else ""
            breakdown.reasoning.append(
                f"IP MALICIOUS{c2_label} (confidence={ip_enrich.confidence_score}) "
                f"→ điểm ip: {score:.2f}"
            )
            return score

        else:  # UNKNOWN
            breakdown.reasoning.append(
                f"IP UNKNOWN ({ip_enrich.ip_address}) → điểm ip: 0.10"
            )
            return 0.10

    def _score_asset(
        self,
        criticality: AssetCriticality,
        breakdown: ScoringBreakdown
    ) -> float:
        """
        Tính điểm từ asset criticality.

        Critical host → score cao hơn vì business impact lớn hơn.
        """
        score = self._ASSET_SCORES.get(criticality, 0.45)
        breakdown.reasoning.append(
            f"Asset criticality: {criticality.value} → điểm asset: {score}"
        )
        return score

    def _score_severity(
        self,
        severity: Severity,
        breakdown: ScoringBreakdown
    ) -> float:
        """
        Tính điểm từ severity của alert gốc (từ EDR).

        EDR severity là signal hữu ích nhưng không đủ mạnh một mình
        (có thể false positive), nên trọng số thấp nhất.
        """
        score = self._SEVERITY_SCORES.get(severity, 0.45)
        breakdown.reasoning.append(
            f"Alert severity: {severity.value} → điểm severity: {score}"
        )
        return score

    def _score_mitre(
        self,
        mappings: List[MITREMapping],
        breakdown: ScoringBreakdown
    ) -> float:
        """
        Tính điểm từ MITRE ATT&CK technique mappings.

        Lấy severity_weight cao nhất trong các technique matched.
        Số lượng technique càng nhiều → slight bonus.
        """
        if not mappings:
            breakdown.reasoning.append("MITRE: không match technique nào → điểm mitre: 0.0")
            return 0.0

        max_weight = max(m.confidence for m in mappings)
        # Bonus nhỏ cho mỗi technique thêm (tối đa 0.15 bonus)
        count_bonus = min(0.15, (len(mappings) - 1) * 0.05)
        score = min(1.0, max_weight + count_bonus)

        techniques = [f"{m.technique_id}({m.tactic})" for m in mappings[:3]]
        breakdown.reasoning.append(
            f"MITRE: {len(mappings)} technique(s) matched "
            f"[{', '.join(techniques)}{'...' if len(mappings) > 3 else ''}] "
            f"→ điểm mitre: {score:.2f}"
        )
        return score

    @staticmethod
    def _determine_level(score: float) -> str:
        """
        Chuyển đổi numeric score → risk level label.

        Ngưỡng:
          0  – 25  → low
          26 – 50  → medium
          51 – 75  → high
          76 – 100 → critical
        """
        if score <= 25.0:
            return "low"
        elif score <= 50.0:
            return "medium"
        elif score <= 75.0:
            return "high"
        else:
            return "critical"
