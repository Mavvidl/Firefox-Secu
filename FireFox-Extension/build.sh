#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🔧 Build SecureWeb Analyzer - Extension Firefox Rust/Wasm"
echo "========================================================"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# FR: Vérifier les commandes nécessaires pour construire le projet
# EN: Check required commands/tools to build the project
echo -e "\n${YELLOW}📋 Vérification des prérequis...${NC}"

if ! command -v cargo &> /dev/null; then
    echo -e "${RED}❌ Rust/Cargo n'est pas installé. https://rustup.rs${NC}"
    exit 1
fi

if ! command -v wasm-pack &> /dev/null; then
    echo -e "${YELLOW}📦 Installation de wasm-pack...${NC}"
    cargo install wasm-pack
fi

echo -e "${GREEN}✅ Prérequis OK${NC}"

# FR: Nettoyer les artefacts de build précédents
# EN: Clean previous build artifacts
echo -e "\n${YELLOW}🧹 Nettoyage...${NC}"
rm -rf extension/lib/
mkdir -p extension/lib/

# FR: Construire le module Rust -> Wasm via `wasm-pack`
# EN: Build Rust -> Wasm module using `wasm-pack`
echo -e "\n${YELLOW}🦀 Compilation Rust → Wasm...${NC}"
cd src/rust

# Build release avec optimisation pour la taille
wasm-pack build \
    --target web \
    --release \
    --out-dir ../../extension/lib/ \
    --no-typescript

cd ../..

echo -e "${GREEN}✅ Module Wasm compilé${NC}"

# Renommer les fichiers pour plus de clarté
if [ -f "extension/lib/wasm_analyzer.js" ]; then
    echo -e "${GREEN}✅ Fichier glue JS généré${NC}"
fi

if [ -f "extension/lib/wasm_analyzer_bg.wasm" ]; then
    echo -e "${GREEN}✅ Binaire Wasm généré${NC}"
    
    # Afficher la taille
    SIZE=$(du -h "extension/lib/wasm_analyzer_bg.wasm" | cut -f1)
    echo -e "${GREEN}📦 Taille du binaire : ${SIZE}${NC}"
fi

# Créer le zip pour Firefox
echo -e "\n${YELLOW}📦 Création du package pour Firefox...${NC}"
mkdir -p dist
cd extension
zip -r ../dist/secureweb-analyzer-firefox.zip . \
    -x "*.git*" -x "*.DS_Store" -x "*/.git/*"
cd ..

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}✅ Build terminé avec succès !${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "\n📁 Package : dist/secureweb-analyzer-firefox.zip"
echo -e "\nPour tester dans Firefox :"
echo -e "  1. Ouvrir about:debugging#/runtime/this-firefox"
echo -e "  2. Cliquer sur 'Charger un module complémentaire temporaire'"
echo -e "  3. Sélectionner extension/manifest.json"
echo -e "\nOu utiliser web-ext :"
echo -e "  cd extension && web-ext run"