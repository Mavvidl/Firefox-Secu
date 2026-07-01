use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::collections::HashSet;
use std::net::IpAddr;
use url::Url;
use wasm_bindgen::prelude::*;
use std::time::Instant;

/// Résultat d'analyse pour une URL ou un contenu
/// EN: Analysis result for a URL or content
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AnalysisResult {
    /// Score de risque (0.0 = safe, 1.0 = critique)
    /// EN: Risk score (0.0 = safe, 1.0 = critical)
    pub risk_score: f64,
    /// Niveau de menace textuel
    /// EN: Textual threat level
    pub threat_level: String,
    /// Liste des menaces détectées
    /// EN: List of detected threats
    pub threats: Vec<Threat>,
    /// Empreinte SHA-256 du contenu analysé
    /// EN: SHA-256 fingerprint of the analyzed content
    pub content_hash: String,
    /// Temps d'analyse en microsecondes
    /// EN: Analysis time in microseconds
    pub analysis_time_us: u64,
}

/// Représente une menace détectée
/// EN: Represents a detected threat
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Threat {
    pub category: String,
    pub severity: String,
    pub description: String,
    pub matched_pattern: Option<String>,
}

/// Hook personnalisé pour détection
/// EN: Custom detection hook
#[derive(Debug, Clone)]
pub struct CustomHook {
    pub target: String,
    pub pattern: Regex,
    pub category: String,
    pub severity: String,
    pub description: String,
}

/// Configuration de l'analyseur
#[derive(Serialize, Deserialize, Debug)]
pub struct AnalyzerConfig {
    pub enable_url_analysis: bool,
    pub enable_content_analysis: bool,
    pub enable_script_detection: bool,
    pub enable_crypto_checks: bool,
    pub custom_blocklist: Vec<String>,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            enable_url_analysis: true,
            enable_content_analysis: true,
            enable_script_detection: true,
            enable_crypto_checks: false,
            custom_blocklist: Vec::new(),
        }
    }
}

/// Analyseur principal
#[wasm_bindgen]
pub struct SecurityAnalyzer {
    config: AnalyzerConfig,
    // Patterns de détection pré-compilés
    phishing_patterns: Vec<Regex>,
    malware_url_patterns: Vec<Regex>,
    suspicious_script_patterns: Vec<Regex>,
    known_threat_domains: HashSet<String>,
    crypto_stealer_patterns: Vec<Regex>,
    custom_hooks: Vec<CustomHook>,
    // Statistiques
    total_analyzed: u64,
    total_threats: u64,
}

#[wasm_bindgen]
impl SecurityAnalyzer {
    /// Crée une nouvelle instance de l'analyseur
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        // Initialiser les patterns de détection
        let phishing_patterns = vec![
            Regex::new(r"(?i)login|signin|account|password|credential|verify|secure|banking").unwrap(),
            Regex::new(r"(?i)update.*(?:account|payment|billing)").unwrap(),
            Regex::new(r"(?i)(?:free|win|prize|lottery|lucky).*\$.+").unwrap(),
            Regex::new(r"(?i)(?:paypal|amazon|apple|google|microsoft|facebook).*(?:login|verify|confirm)").unwrap(),
        ];

        let malware_url_patterns = vec![
            Regex::new(r"(?i)\.(?:exe|dll|scr|bat|ps1|vbs|jar|apk|msi)\.(?:com|net|org|xyz|top|gq|ml|tk)").unwrap(),
            Regex::new(r"(?i)(?:download|get|file|dl).*(?:\.exe|\.zip|\.rar)").unwrap(),
            Regex::new(r"(?i)(?:redirect|goto|out|track|click)\?.*(?:url|to|link|r)=http").unwrap(),
            Regex::new(r"(?i)\d{1,3}(?:\.\d{1,3}){3}:\d{4,}").unwrap(), // IP:Port suspects
        ];

        let suspicious_script_patterns = vec![
            Regex::new(r"(?i)eval\s*\(\s*(?:typeof|constructor|prototype)").unwrap(),
            Regex::new(r"(?i)document\.write\s*\(\s*(?:atob|fromCharCode)").unwrap(),
            Regex::new(r"(?i)(?:base64|btoa|atob).*(?:eval|Function|setTimeout)").unwrap(),
            Regex::new(r"(?i)(?:document\.cookie|navigator|screen|location)\s*=").unwrap(),
            Regex::new(r#"(?i)(?:String\.fromCharCode|\\x[0-9a-f]{2}){10,}"#).unwrap(),
            Regex::new(r#"(?i)new\s+Function\s*\(.*['"].*['"]\s*\)"#).unwrap(),
            Regex::new(r"(?i)(?:onerror|onload|onmouseover)\s*=\s*(?:eval|Function)").unwrap(),
        ];

        let crypto_stealer_patterns = vec![
            Regex::new(r"(?i)(?:bitcoin|btc|eth|ethereum|wallet|metamask|phantom|keplr)").unwrap(),
            Regex::new(r"(?i)(?:mnemonic|seed.?phrase|private.?key|keystore)").unwrap(),
            Regex::new(r"(?i)(?:connect|import).*(?:wallet|account)").unwrap(),
        ];

        // Domaines de menace connus (liste compacte)
        let known_threat_domains: HashSet<String> = [
            "malware-site.xyz", "phishing-login.tk", "steal-info.gq",
            "fake-bank.ml", "crypto-scam.top", "ransomware.cf",
        ].iter().map(|s| s.to_string()).collect();

        Self {
            config: AnalyzerConfig::default(),
            phishing_patterns,
            malware_url_patterns,
            suspicious_script_patterns,
            known_threat_domains,
            crypto_stealer_patterns,
            custom_hooks: Vec::new(),
            total_analyzed: 0,
            total_threats: 0,
        }
    }

    fn new_threat(&self, category: &str, severity: &str, description: &str, matched_pattern: Option<String>) -> Threat {
        Threat {
            category: category.into(),
            severity: severity.into(),
            description: description.into(),
            matched_pattern,
        }
    }

    fn threat_level_from_score(score: f64) -> &'static str {
        if score >= 0.7 {
            "CRITICAL"
        } else if score >= 0.4 {
            "HIGH"
        } else if score >= 0.2 {
            "MEDIUM"
        } else if score >= 0.05 {
            "LOW"
        } else {
            "SAFE"
        }
    }

    fn run_custom_hooks(&self, target: &str, text: &str, threats: &mut Vec<Threat>, risk_score: &mut f64) {
        for hook in &self.custom_hooks {
            if hook.target != target {
                continue;
            }

            if hook.pattern.is_match(text) {
                threats.push(self.new_threat(
                    &hook.category,
                    &hook.severity,
                    &hook.description,
                    Some(hook.pattern.as_str().to_string()),
                ));

                *risk_score += match hook.severity.to_lowercase().as_str() {
                    "critical" => 0.7,
                    "high" => 0.4,
                    "medium" => 0.2,
                    "low" => 0.1,
                    _ => 0.05,
                };
            }
        }
    }

    fn finalize_result(&mut self, risk_score: f64, threats: Vec<Threat>, content_hash: String, start: Instant) -> JsValue {
        let threat_level = Self::threat_level_from_score(risk_score).to_string();
        if !threats.is_empty() {
            self.total_threats += 1;
        }

        let elapsed = start.elapsed().as_micros() as u64;
        let result = AnalysisResult {
            risk_score,
            threat_level,
            threats,
            content_hash,
            analysis_time_us: elapsed,
        };

        serde_wasm_bindgen::to_value(&result).unwrap()
    }

    /// Analyse une URL complète
    pub fn analyze_url(&mut self, url_str: &str) -> JsValue {
        let start = Instant::now();
        self.total_analyzed += 1;

        let mut threats: Vec<Threat> = Vec::new();
        let mut risk_score: f64 = 0.0;

        if !self.config.enable_url_analysis {
            let mut hasher = Sha256::new();
            hasher.update(url_str.as_bytes());
            let content_hash = format!("{:x}", hasher.finalize());
            return self.finalize_result(risk_score, threats, content_hash, start);
        }

        // Parser l'URL
        if let Ok(parsed) = Url::parse(url_str) {
            let host = parsed.host_str().unwrap_or("");
            let path = parsed.path();
            let query = parsed.query().unwrap_or("");
            let full = if query.is_empty() {
                format!("{}://{}{}", parsed.scheme(), host, path)
            } else {
                format!("{}://{}{}?{}", parsed.scheme(), host, path, query)
            };

            if self.config.custom_blocklist.iter().any(|d| d.eq_ignore_ascii_case(host)) {
                threats.push(self.new_threat(
                    "blacklist",
                    "critical",
                    &format!("Domaine ajouté à la liste noire : {}", host),
                    Some(host.into()),
                ));
                risk_score += 0.9;
            }

            // 1. Vérification HTTPS
            if parsed.scheme() != "https" && parsed.scheme() != "wss" {
                threats.push(self.new_threat(
                    "connection",
                    "medium",
                    "Connexion non chiffrée (HTTP au lieu de HTTPS)",
                    Some(parsed.scheme().into()),
                ));
                risk_score += 0.15;
            }

            // 2. Domaines suspects
            if self.known_threat_domains.contains(host) {
                threats.push(self.new_threat(
                    "blacklist",
                    "critical",
                    &format!("Domaine présent dans la liste noire : {}", host),
                    Some(host.into()),
                ));
                risk_score += 0.8;
            }

            // 3. Patterns malveillants dans l'URL
            for pattern in &self.malware_url_patterns {
                if let Some(mat) = pattern.find(&full) {
                    threats.push(self.new_threat(
                        "malware_url",
                        "high",
                        "Pattern d'URL malveillante détecté",
                        Some(mat.as_str().to_string()),
                    ));
                    risk_score += 0.5;
                }
            }

            // 4. Patterns de phishing
            for pattern in &self.phishing_patterns {
                if let Some(mat) = pattern.find(&full) {
                    threats.push(self.new_threat(
                        "phishing",
                        "high",
                        "Tentative de phishing détectée",
                        Some(mat.as_str().to_string()),
                    ));
                    risk_score += 0.4;
                }
            }

            // 5. Sous-domaines suspects (ex: compte-paypal.xyz.com)
            let subdomain_count = host.matches('.').count();
            if subdomain_count > 3 {
                threats.push(self.new_threat(
                    "suspicious_domain",
                    "low",
                    "Nombre anormal de sous-domaines",
                    Some(host.into()),
                ));
                risk_score += 0.1;
            }

            // 6. URL raccourcie ou suspecte
            let shortening_domains = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "shorturl.at"];
            if shortening_domains.iter().any(|d| host.contains(d)) {
                threats.push(self.new_threat(
                    "url_shortener",
                    "medium",
                    "Utilisation d'un service de raccourcissement d'URL",
                    Some(host.into()),
                ));
                risk_score += 0.25;
            }

            // 7. Adresse IP directe
            if let Ok(ip) = host.parse::<IpAddr>() {
                threats.push(self.new_threat(
                    "ip_address",
                    "low",
                    &format!("Accès direct à une adresse IP : {}", ip),
                    Some(host.into()),
                ));
                risk_score += 0.15;
            }

            self.run_custom_hooks("url", &full, &mut threats, &mut risk_score);
        } else {
            threats.push(self.new_threat(
                "invalid_url",
                "low",
                "L'URL n'a pas pu être parsée",
                None,
            ));
            risk_score += 0.1;
        }

        // Calcul du hash du contenu (ici de l'URL elle-même)
        let mut hasher = Sha256::new();
        hasher.update(url_str.as_bytes());
        let content_hash = format!("{:x}", hasher.finalize());

        // Clamper le score entre 0 et 1
        risk_score = risk_score.clamp(0.0, 1.0);

        self.finalize_result(risk_score, threats, content_hash, start)
    }

    /// Analyse le contenu textuel d'une page (scripts, HTML, etc.)
    pub fn analyze_content(&mut self, content: &str) -> JsValue {
        let start = Instant::now();
        self.total_analyzed += 1;

        let mut threats: Vec<Threat> = Vec::new();
        let mut risk_score: f64 = 0.0;

        if !self.config.enable_content_analysis {
            let mut hasher = Sha256::new();
            hasher.update(content.as_bytes());
            let content_hash = format!("{:x}", hasher.finalize());
            return self.finalize_result(risk_score, threats, content_hash, start);
        }

        // 1. Scripts suspects
        if self.config.enable_script_detection {
            for pattern in &self.suspicious_script_patterns {
                if let Some(mat) = pattern.find(content) {
                    threats.push(self.new_threat(
                        "suspicious_script",
                        "high",
                        "Pattern de script JavaScript suspect détecté",
                        Some(mat.as_str().to_string()),
                    ));
                    risk_score += 0.35;
                }
            }
        }

        // 2. Vol de cryptomonnaies
        if self.config.enable_crypto_checks {
            for pattern in &self.crypto_stealer_patterns {
                if let Some(mat) = pattern.find(content) {
                    threats.push(self.new_threat(
                        "crypto_stealer",
                        "high",
                        "Pattern de vol de cryptomonnaie détecté",
                        Some(mat.as_str().to_string()),
                    ));
                    risk_score += 0.45;
                }
            }
        }

        // 3. Détection de data URIs suspects
        let data_uri_count = Regex::new(r"(?i)data:").unwrap().find_iter(content).count();
        if data_uri_count > 5 {
            threats.push(self.new_threat(
                "data_uri_abuse",
                "medium",
                &format!("Nombre anormal de data URIs ({})", data_uri_count),
                None,
            ));
            risk_score += 0.2;
        }

        // 4. Détection d'iframes cachés
        let iframe_count = Regex::new(r"(?i)<iframe").unwrap().find_iter(content).count();
        if iframe_count > 3 {
            threats.push(self.new_threat(
                "hidden_iframes",
                "medium",
                &format!("Nombre anormal d'iframes ({})", iframe_count),
                None,
            ));
            risk_score += 0.25;
        }

        // 5. Redirections JavaScript
        let redirect_patterns = [
            r"window\.location\s*=",
            r"document\.location\s*=",
            r"location\.href\s*=",
            r"location\.replace\(",
        ];
        for pat_str in &redirect_patterns {
            if let Ok(re) = Regex::new(pat_str) {
                if re.is_match(content) {
                    threats.push(self.new_threat(
                        "redirect",
                        "low",
                        "Redirection JavaScript détectée",
                        Some(pat_str.to_string()),
                    ));
                    risk_score += 0.1;
                    break;
                }
            }
        }

        self.run_custom_hooks("content", content, &mut threats, &mut risk_score);

        // Calcul du hash du contenu
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let content_hash = format!("{:x}", hasher.finalize());

        risk_score = risk_score.clamp(0.0, 1.0);

        self.finalize_result(risk_score, threats, content_hash, start)
    }

    /// Configure l'analyseur dynamiquement
    pub fn configure(&mut self, config: JsValue) {
        if let Ok(cfg) = serde_wasm_bindgen::from_value::<AnalyzerConfig>(config) {
            self.config = cfg;
        }
    }

    /// Enregistre un hook de détection personnalisé (url ou content)
    pub fn register_hook(&mut self, target: &str, regex: &str, category: &str, severity: &str, description: &str) -> bool {
        if target != "url" && target != "content" {
            return false;
        }

        if let Ok(pattern) = Regex::new(regex) {
            self.custom_hooks.push(CustomHook {
                target: target.to_string(),
                pattern,
                category: category.to_string(),
                severity: severity.to_string(),
                description: description.to_string(),
            });
            true
        } else {
            false
        }
    }

    /// Analyse un événement en temps réel selon son type
    pub fn scan_event(&mut self, event_type: &str, data: &str) -> JsValue {
        match event_type {
            "url" => self.analyze_url(data),
            "content" => self.analyze_content(data),
            _ => self.analyze_content(data),
        }
    }

    /// Ajoute un domaine à la liste noire
    pub fn add_to_blocklist(&mut self, domain: &str) {
        self.known_threat_domains.insert(domain.to_string());
    }

    /// Retourne les statistiques
    pub fn get_stats(&self) -> JsValue {
        let stats = serde_json::json!({
            "total_analyzed": self.total_analyzed,
            "total_threats": self.total_threats,
            "threat_ratio": if self.total_analyzed > 0 {
                self.total_threats as f64 / self.total_analyzed as f64
            } else {
                0.0
            }
        });
        serde_wasm_bindgen::to_value(&stats).unwrap()
    }

    /// Analyse rapide pour les appels synchrones
    pub fn quick_scan(&mut self, data: &str, is_url: bool) -> String {
        let result = if is_url {
            self.analyze_url(data)
        } else {
            self.analyze_content(data)
        };
        if let Ok(r) = serde_wasm_bindgen::from_value::<AnalysisResult>(result) {
            format!(
                "[{}] Score: {:.2} | Menaces: {} | {}",
                r.threat_level,
                r.risk_score,
                r.threats.len(),
                r.threats.first()
                    .map(|t| t.description.as_str())
                    .unwrap_or("Aucune menace")
            )
        } else {
            "Erreur d'analyse".into()
        }
    }
}
