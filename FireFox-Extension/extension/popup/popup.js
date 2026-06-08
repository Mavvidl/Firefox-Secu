// ==============================================================
// SecureWeb Analyzer — Popup Script
// ==============================================================

document.addEventListener('DOMContentLoaded', async () => {
    // État
    let currentTabId = null;
    
    // Obtenir l'onglet actif
    try {
        const tabs = await browser.tabs.query({ active: true, currentWindow: true });
        if (tabs && tabs.length > 0) {
            currentTabId = tabs[0].id;
            document.getElementById('current-url').textContent = tabs[0].url || 'URL inconnue';
        }
    } catch (err) {
        console.error('Erreur onglet:', err);
    }
    
    // Charger les données de l'onglet
    if (currentTabId) {
        try {
            const response = await browser.runtime.sendMessage({
                action: 'get_tab_data',
                tabId: currentTabId
            });
            
            if (response) {
                displayAnalysisResult(response.result);
            } else {
                // Analyser l'URL maintenant
                const tabs = await browser.tabs.query({ active: true, currentWindow: true });
                if (tabs[0]?.url && !tabs[0].url.startsWith('about:')) {
                    const result = await browser.runtime.sendMessage({
                        action: 'analyze_url',
                        url: tabs[0].url
                    });
                    if (result) {
                        displayAnalysisResult(result);
                    }
                }
            }
        } catch (err) {
            console.error('Erreur chargement données:', err);
        }
    }
    
    // Charger les statistiques globales
    try {
        const stats = await browser.runtime.sendMessage({ action: 'get_stats' });
        if (stats) {
            document.getElementById('total-analyzed').textContent = stats.total_analyzed;
            document.getElementById('total-threats').textContent = stats.total_threats;
            document.getElementById('threat-ratio').textContent = 
                (stats.threat_ratio * 100).toFixed(1) + '%';
        }
    } catch (err) {
        console.error('Erreur stats:', err);
    }
    
    // Charger la configuration
    try {
        const stored = await browser.storage.local.get('config');
        if (stored.config) {
            document.getElementById('enable-url').checked = stored.config.enable_url_analysis;
            document.getElementById('enable-content').checked = stored.config.enable_content_analysis;
            document.getElementById('enable-scripts').checked = stored.config.enable_script_detection;
            document.getElementById('enable-crypto').checked = stored.config.enable_crypto_checks;
        }
    } catch (err) {
        console.error('Erreur config:', err);
    }
    
    // Sauvegarde de la configuration
    document.getElementById('save-config').addEventListener('click', async () => {
        const config = {
            enable_url_analysis: document.getElementById('enable-url').checked,
            enable_content_analysis: document.getElementById('enable-content').checked,
            enable_script_detection: document.getElementById('enable-scripts').checked,
            enable_crypto_checks: document.getElementById('enable-crypto').checked
        };
        
        try {
            await browser.runtime.sendMessage({
                action: 'configure',
                config: config
            });
            
            const btn = document.getElementById('save-config');
            btn.textContent = '✅ Sauvegardé !';
            setTimeout(() => {
                btn.textContent = 'Sauvegarder';
            }, 2000);
        } catch (err) {
            console.error('Erreur sauvegarde config:', err);
        }
    });
});

// Affiche le résultat d'analyse
function displayAnalysisResult(result) {
    const threatLevelEl = document.getElementById('threat-level');
    const riskScoreEl = document.getElementById('risk-score');
    const threatCountEl = document.getElementById('threat-count');
    const threatDetails = document.getElementById('threat-details');
    const threatList = document.getElementById('threat-list');
    
    // Déterminer la classe CSS
    const level = (result.threat_level || 'SAFE').toLowerCase();
    let statusClass = 'threat-safe';
    
    switch (level) {
        case 'critical': statusClass = 'threat-critical'; break;
        case 'high': statusClass = 'threat-high'; break;
        case 'medium': statusClass = 'threat-medium'; break;
        case 'low': statusClass = 'threat-low'; break;
        default: statusClass = 'threat-safe';
    }
    
    threatLevelEl.className = statusClass;
    threatLevelEl.textContent = result.threat_level || 'SAFE';
    riskScoreEl.textContent = (result.risk_score * 100).toFixed(1) + '%';
    
    // Menaces
    const threats = result.threats || [];
    threatCountEl.textContent = threats.length;
    
    if (threats.length > 0) {
        threatDetails.classList.remove('hidden');
        threatList.innerHTML = threats.map(t => 
            `<li><strong>[${t.severity.toUpperCase()}]</strong> ${t.description}${t.matched_pattern ? `<br><code>${escapeHtml(t.matched_pattern)}</code>` : ''}</li>`
        ).join('');
    } else {
        threatDetails.classList.add('hidden');
    }
    
    // Temps d'analyse
    const timeEl = document.createElement('div');
    timeEl.style.cssText = 'font-size: 10px; color: var(--text-secondary); margin-top: 4px;';
    timeEl.textContent = `Analyse en ${result.analysis_time_us}µs`;
    document.querySelector('.result-box').appendChild(timeEl);
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}