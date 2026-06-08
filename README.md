# 🔒 SecureWeb Analyzer

Extension Firefox de **sécurité défensive** qui analyse le trafic Web en temps réel.

Le **moteur d'analyse est écrit en Rust et compilé en WebAssembly** pour des performances maximales et une sécurité mémoire garantie, tandis qu'une fine couche JavaScript interface avec l'API WebExtensions de Firefox.

## Architecture


┌────────────────────────────────────────────────────────────┐
│                     NAVIGATEUR FIREFOX                      │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │               EXTENSION SecureWeb                     │  │
│  │                                                      │  │
│  │  ┌──────────────────┐     ┌──────────────────────┐   │  │
│  │  │   background.js   │     │     wasm_analyzer    │   │  │
│  │  │                   │     │                      │   │  │
│  │  │  Pont JavaScript  │◄───►│  🦀 Rust → ⚡ Wasm   │   │  │
│  │  │  vers le moteur   │     │                      │   │  │
│  │  │  WebAssembly      │     │  • Analyse d'URLs    │   │  │
│  │  │                   │     │  • Détection         │   │  │
│  │  │  browser.         │     │    de phishing       │   │  │
│  │  │  webRequest.on*   │     │  • Scan de           │   │  │
│  │  │                   │     │    contenu JS        │   │  │
│  │  │  StreamFilter     │     │  • Reconnaissance    │   │  │
│  │  │  (réponses)       │     │    de malwares       │   │  │
│  │  │                   │     │  • Anti-crypto-      │   │  │
│  │  │                   │     │    stealers          │   │  │
│  │  └──────────────────┘     └──────────────────────┘   │  │
│  │                                                      │  │
│  │  ┌──────────────────────────────────────────────┐    │  │
│  │  │                Popup (interface)              │    │  │
│  │  │  • Résultat en temps réel                    │    │  │
│  │  │  • Statistiques globales                     │    │  │
│  │  │  • Configuration dynamique                   │    │  │
│  │  └──────────────────────────────────────────────┘    │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                            │
│  API utilisée : browser.webRequest + filterResponseData    │
│  Interception de TOUT le trafic HTTP(S)                    │
└────────────────────────────────────────────────────────────┘




# 1. Rust (≥ 1.70)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. wasm-pack (compilateur Rust → Wasm)
cargo install wasm-pack

# 3. Optionnel : web-ext (lancement Firefox en dev)
npm install -g web-ext




#
