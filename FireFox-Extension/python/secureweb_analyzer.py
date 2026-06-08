#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse


@dataclass
class Threat:
    category: str
    severity: str
    description: str
    matched_pattern: Optional[str] = None


@dataclass
class AnalysisResult:
    risk_score: float
    threat_level: str
    threats: List[Threat]
    content_hash: str
    analysis_time_us: int


class SecurityAnalyzer:
    def __init__(self):
        self.enable_url_analysis = True
        self.enable_content_analysis = True
        self.enable_script_detection = True
        self.enable_crypto_checks = False
        self.custom_blocklist: List[str] = []

        self.phishing_patterns = [
            re.compile(r"(?i)login|signin|account|password|credential|verify|secure|banking"),
            re.compile(r"(?i)update.*(?:account|payment|billing)"),
            re.compile(r"(?i)(?:free|win|prize|lottery|lucky).*\$.+"),
            re.compile(r"(?i)(?:paypal|amazon|apple|google|microsoft|facebook).*(?:login|verify|confirm)"),
        ]

        self.malware_url_patterns = [
            re.compile(r"(?i)\.(?:exe|dll|scr|bat|ps1|vbs|jar|apk|msi)\.(?:com|net|org|xyz|top|gq|ml|tk)"),
            re.compile(r"(?i)(?:download|get|file|dl).*(?:\.exe|\.zip|\.rar)"),
            re.compile(r"(?i)(?:redirect|goto|out|track|click)\?.*(?:url|to|link|r)=http"),
            re.compile(r"(?i)\d{1,3}(?:\.\d{1,3}){3}:\d{4,}"),
        ]

        self.suspicious_script_patterns = [
            re.compile(r"(?i)eval\s*\(\s*(?:typeof|constructor|prototype)"),
            re.compile(r"(?i)document\.write\s*\(\s*(?:atob|fromCharCode)"),
            re.compile(r"(?i)(?:base64|btoa|atob).*(?:eval|Function|setTimeout)"),
            re.compile(r"(?i)(?:document\.cookie|navigator|screen|location)\s*="),
            re.compile(r"(?i)(?:String\.fromCharCode|\\x[0-9a-f]{2}){10,}"),
            re.compile(r"(?i)new\s+Function\s*\(.*['\"].*['\"]\s*\)"),
            re.compile(r"(?i)(?:onerror|onload|onmouseover)\s*=\s*(?:eval|Function)"),
        ]

        self.crypto_stealer_patterns = [
            re.compile(r"(?i)(?:bitcoin|btc|eth|ethereum|wallet|metamask|phantom|keplr)"),
            re.compile(r"(?i)(?:mnemonic|seed.?phrase|private.?key|keystore)"),
            re.compile(r"(?i)(?:connect|import).*(?:wallet|account)"),
        ]

        self.known_threat_domains = {
            "malware-site.xyz",
            "phishing-login.tk",
            "steal-info.gq",
            "fake-bank.ml",
            "crypto-scam.top",
            "ransomware.cf",
        }

    def _hash(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _threat_level(self, score: float) -> str:
        if score >= 0.7:
            return "CRITICAL"
        if score >= 0.4:
            return "HIGH"
        if score >= 0.2:
            return "MEDIUM"
        if score >= 0.05:
            return "LOW"
        return "SAFE"

    def _make_threat(self, category: str, severity: str, description: str, matched_pattern: Optional[str] = None) -> Threat:
        return Threat(category=category, severity=severity, description=description, matched_pattern=matched_pattern)

    def analyze_url(self, url_str: str) -> AnalysisResult:
        if not self.enable_url_analysis:
            return AnalysisResult(
                risk_score=0.0,
                threat_level="SAFE",
                threats=[],
                content_hash=self._hash(url_str),
                analysis_time_us=0,
            )

        threats: List[Threat] = []
        risk_score = 0.0
        parsed = urlparse(url_str)
        host = parsed.hostname or ""
        full = parsed.geturl()

        if any(domain.lower() == host.lower() for domain in self.custom_blocklist):
            threats.append(self._make_threat(
                "blacklist",
                "critical",
                f"Domaine ajouté à la liste noire : {host}",
                host,
            ))
            risk_score += 0.9

        if parsed.scheme not in {"https", "wss"}:
            threats.append(self._make_threat(
                "connection",
                "medium",
                "Connexion non chiffrée (HTTP au lieu de HTTPS)",
                parsed.scheme,
            ))
            risk_score += 0.15

        if host in self.known_threat_domains:
            threats.append(self._make_threat(
                "blacklist",
                "critical",
                f"Domaine présent dans la liste noire : {host}",
                host,
            ))
            risk_score += 0.8

        for pattern in self.malware_url_patterns:
            match = pattern.search(full)
            if match:
                threats.append(self._make_threat(
                    "malware_url",
                    "high",
                    "Pattern d'URL malveillante détecté",
                    match.group(0),
                ))
                risk_score += 0.5

        for pattern in self.phishing_patterns:
            match = pattern.search(full)
            if match:
                threats.append(self._make_threat(
                    "phishing",
                    "high",
                    "Tentative de phishing détectée",
                    match.group(0),
                ))
                risk_score += 0.4

        if host.count(".") > 3:
            threats.append(self._make_threat(
                "suspicious_domain",
                "low",
                "Nombre anormal de sous-domaines",
                host,
            ))
            risk_score += 0.1

        if any(short in host for short in ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "shorturl.at"]):
            threats.append(self._make_threat(
                "url_shortener",
                "medium",
                "Utilisation d'un service de raccourcissement d'URL",
                host,
            ))
            risk_score += 0.25

        if host:
            try:
                _ = IpAddr(host)
                threats.append(self._make_threat(
                    "ip_address",
                    "low",
                    f"Accès direct à une adresse IP : {host}",
                    host,
                ))
                risk_score += 0.15
            except ValueError:
                pass

        risk_score = min(max(risk_score, 0.0), 1.0)

        return AnalysisResult(
            risk_score=risk_score,
            threat_level=self._threat_level(risk_score),
            threats=threats,
            content_hash=self._hash(url_str),
            analysis_time_us=0,
        )

    def analyze_content(self, content: str) -> AnalysisResult:
        if not self.enable_content_analysis:
            return AnalysisResult(
                risk_score=0.0,
                threat_level="SAFE",
                threats=[],
                content_hash=self._hash(content),
                analysis_time_us=0,
            )

        threats: List[Threat] = []
        risk_score = 0.0

        if self.enable_script_detection:
            for pattern in self.suspicious_script_patterns:
                match = pattern.search(content)
                if match:
                    threats.append(self._make_threat(
                        "suspicious_script",
                        "high",
                        "Pattern de script JavaScript suspect détecté",
                        match.group(0),
                    ))
                    risk_score += 0.35

        if self.enable_crypto_checks:
            for pattern in self.crypto_stealer_patterns:
                match = pattern.search(content)
                if match:
                    threats.append(self._make_threat(
                        "crypto_stealer",
                        "high",
                        "Pattern de vol de cryptomonnaie détecté",
                        match.group(0),
                    ))
                    risk_score += 0.45

        data_uri_count = len(re.findall(r"(?i)data:", content))
        if data_uri_count > 5:
            threats.append(self._make_threat(
                "data_uri_abuse",
                "medium",
                f"Nombre anormal de data URIs ({data_uri_count})",
                None,
            ))
            risk_score += 0.2

        iframe_count = len(re.findall(r"(?i)<iframe", content))
        if iframe_count > 3:
            threats.append(self._make_threat(
                "hidden_iframes",
                "medium",
                f"Nombre anormal d'iframes ({iframe_count})",
                None,
            ))
            risk_score += 0.25

        redirect_patterns = [
            r"window\.location\s*=",
            r"document\.location\s*=",
            r"location\.href\s*=",
            r"location\.replace\(",
        ]
        for pat_str in redirect_patterns:
            if re.search(pat_str, content):
                threats.append(self._make_threat(
                    "redirect",
                    "low",
                    "Redirection JavaScript détectée",
                    pat_str,
                ))
                risk_score += 0.1
                break

        risk_score = min(max(risk_score, 0.0), 1.0)

        return AnalysisResult(
            risk_score=risk_score,
            threat_level=self._threat_level(risk_score),
            threats=threats,
            content_hash=self._hash(content),
            analysis_time_us=0,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Prototype SecureWeb Analyzer en Python")
    parser.add_argument("--url", help="URL à analyser")
    parser.add_argument("--content", help="Contenu texte à analyser")
    parser.add_argument("--content-file", help="Fichier contenant le contenu à analyser")
    parser.add_argument("--enable-crypto", action="store_true", help="Activer la détection de contenu crypto")
    parser.add_argument("--blocklist", nargs="*", default=[], help="Liste de domaines personnalisés à bloquer")
    parser.add_argument("--json", action="store_true", help="Afficher le résultat au format JSON")
    args = parser.parse_args()

    analyzer = SecurityAnalyzer()
    analyzer.enable_crypto_checks = args.enable_crypto
    analyzer.custom_blocklist = args.blocklist

    if args.url:
        result = analyzer.analyze_url(args.url)
    elif args.content_file:
        content = Path(args.content_file).read_text(encoding="utf-8")
        result = analyzer.analyze_content(content)
    elif args.content:
        result = analyzer.analyze_content(args.content)
    else:
        parser.print_help()
        return

    if args.json:
        print(json.dumps(asdict(result), ensure_ascii=False, indent=2))
    else:
        print(f"Threat level: {result.threat_level}")
        print(f"Risk score: {result.risk_score:.2f}")
        print(f"Threats: {len(result.threats)}")
        for threat in result.threats:
            print(f"- [{threat.severity}] {threat.description} ({threat.matched_pattern})")


if __name__ == "__main__":
    main()
