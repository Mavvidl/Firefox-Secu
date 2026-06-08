// ==============================================================
// SecureWeb Analyzer — Background Script
// Pont JavaScript <-> WebAssembly pour l'analyse du trafic
// ==============================================================

let analyzer = null;
let wasmInitialized = false;

// Initialisation du module Wasm
async function initWasm() {
    try {
        const wasm = await import('./lib/wasm_analyzer.js');
        await wasm.default();
        analyzer = new wasm.SecurityAnalyzer();
        wasmInitialized = true;
        console.log('[SecureWeb] Moteur Wasm initialisé avec succès');
        
        // Restaurer la configuration depuis le stockage
        const stored = await browser.storage.local.get('config');
        if (stored.config) {
            analyzer.configure(stored.config);
        }
    } catch (err) {
        console.error('[SecureWeb] Erreur d\'initialisation Wasm:', err);
    }
}

// Analyse une requête et retourne le résultat
function analyzeRequest(details) {
    if (!wasmInitialized || !analyzer) return null;
    
    try {
        const urlResult = analyzer.analyze_url(details.url);
        
        // Stocker le résultat pour la popup
        const tabData = {
            url: details.url,
            timestamp: Date.now(),
            result: urlResult
        };
        browser.storage.local.set({ [`tab_${details.tabId}`]: tabData });
        
        return urlResult;
    } catch (err) {
        console.error('[SecureWeb] Erreur d\'analyse:', err);
        return null;
    }
}

// Analyse le contenu de la réponse (scripts, HTML)
function analyzeResponseContent(details, content) {
    if (!wasmInitialized || !analyzer) return;
    
    try {
        const contentResult = analyzer.analyze_content(content);
        
        if (contentResult.risk_score >= 0.4) {
            console.warn(`[SecureWeb] ⚠️  Menace détectée sur ${details.url}`, contentResult);
            
            // Notification si critique
            if (contentResult.risk_score >= 0.7) {
                browser.notifications.create({
                    type: 'basic',
                    iconUrl: 'icons/icon-48.svg',
                    title: '🔴 SecureWeb : Menace critique détectée',
                    message: `${details.url}\n${contentResult.threat_level}: ${contentResult.threats[0]?.description || 'Activité suspecte'}`
                });
            }
        }
        
        return contentResult;
    } catch (err) {
        console.error('[SecureWeb] Erreur d\'analyse de contenu:', err);
    }
}

// ==============================================================
// Écouteurs webRequest
// ==============================================================

// Analyse les requêtes avant leur envoi
browser.webRequest.onBeforeRequest.addListener(
    (details) => {
        const result = analyzeRequest(details);
        if (result && result.risk_score >= 0.7) {
            // Option : bloquer les requêtes critiques
            // return { cancel: true };
        }
        return {};
    },
    { urls: ['<all_urls>'] },
    ['blocking']
);

// Analyse les réponses pour détecter les scripts malveillants
browser.webRequest.onHeadersReceived.addListener(
    (details) => {
        if (details.type === 'script' || details.type === 'main_frame' || details.type === 'sub_frame') {
            // Créer un filtre pour analyser le contenu
            const filter = browser.webRequest.filterResponseData(details.requestId);
            const decoder = new TextDecoder('utf-8');
            const encoder = new TextEncoder();
            let chunks = [];
            
            filter.ondata = (event) => {
                chunks.push(event.data);
                filter.write(event.data);
            };
            
            filter.onstop = () => {
                // Réassembler et analyser le contenu
                const content = chunks.map(c => decoder.decode(c, { stream: true })).join('');
                if (content.length > 0) {
                    analyzeResponseContent(details, content);
                }
                filter.disconnect();
            };
            
            filter.onerror = () => {
                console.error('[SecureWeb] Erreur du filtre de réponse:', filter.error);
                // Écrire quand même les données
                for (const chunk of chunks) {
                    try { filter.write(chunk); } catch(e) {}
                }
                filter.disconnect();
            };
        }
        return {};
    },
    { urls: ['<all_urls>'], types: ['script', 'main_frame', 'sub_frame'] },
    ['blocking']
);

// ==============================================================
// Gestion des messages (depuis la popup)
// ==============================================================

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.action) {
        case 'get_stats':
            if (analyzer) {
                sendResponse(analyzer.get_stats());
            } else {
                sendResponse(null);
            }
            break;
            
        case 'analyze_url':
            if (analyzer) {
                const result = analyzer.analyze_url(message.url);
                sendResponse(result);
            } else {
                sendResponse(null);
            }
            break;
            
        case 'add_to_blocklist':
            if (analyzer) {
                analyzer.add_to_blocklist(message.domain);
                sendResponse({ success: true });
            } else {
                sendResponse({ success: false });
            }
            break;
            
        case 'get_tab_data':
            browser.storage.local.get(`tab_${message.tabId}`).then((data) => {
                sendResponse(data[`tab_${message.tabId}`] || null);
            });
            return true; // Pour les réponses asynchrones
            
        case 'configure':
            if (analyzer) {
                analyzer.configure(message.config);
                browser.storage.local.set({ config: message.config });
                sendResponse({ success: true });
            } else {
                sendResponse({ success: false });
            }
            break;
            
        default:
            sendResponse({ error: 'Action inconnue' });
    }
});

// Nettoyage périodique des données de tabs
setInterval(() => {
    browser.storage.local.get(null).then((data) => {
        const now = Date.now();
        for (const [key, value] of Object.entries(data)) {
            if (key.startsWith('tab_') && now - value.timestamp > 300000) {
                browser.storage.local.remove(key);
            }
        }
    });
}, 60000); // Nettoie toutes les minutes

// Initialisation
initWasm();

console.log('[SecureWeb] Background script chargé');