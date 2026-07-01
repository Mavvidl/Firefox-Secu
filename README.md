# 🔒 SecureWeb Analyzer

SecureWeb Analyzer est une extension Firefox qui analyse localement le trafic Web en temps réel.

Le moteur d'analyse est écrit en Rust et compilé en WebAssembly pour réduire les risques de sécurité et améliorer les performances.

## Structure du dépôt

- `FireFox-Extension/extension/` : code de l'extension WebExtension (manifest, popup, background)
- `FireFox-Extension/src/rust/` : moteur d'analyse Rust compilé en Wasm
- `FireFox-Extension/python/` : prototype d'analyse en Python
- `FireFox-Extension/build.sh` : script de compilation et packaging
- `.github/workflows/build.yml` : workflow GitHub Actions pour compiler et empaqueter l'extension

## Installation

```bash
cd FireFox-Extension
./build.sh
```

## Dépendances

- Rust 1.70+ avec `cargo`
- `wasm-pack` pour compiler le moteur Rust vers Wasm
- Optionnel : `web-ext` pour lancer l'extension en développement

## Sécurité et confidentialité

- L'analyse est entièrement locale : aucun trafic n'est transmis à un service distant.
- Le manifeste utilise un service worker MV3 et une CSP plus stricte pour l'extension.
- L'extension nécessite des permissions larges (`webRequest`, `webRequestBlocking`, `<all_urls>`) : cela doit être contrôlé avant installation.
- Les résultats d'analyse et la configuration sont stockés en local dans `browser.storage.local`.
- Le moteur Rust prend désormais en charge des hooks personnalisés via `register_hook()` pour ajouter des regex de détection URL/contenu en temps réel.

## Améliorations apportées

- Manifest corrigé pour MV3 compatible Firefox
- Ajout de la permission `notifications` pour les alertes critiques
- Amélioration de la sécurité du rendu du popup (suppression de l'usage d'`innerHTML` non nécessaire)
- Meilleure gestion de la config et des données avant initialisation du moteur Wasm
- Script `build.sh` renforcé pour fonctionner depuis son dossier source
- Ajout d'un workflow GitHub Actions pour la compilation et le packaging

## Utilisation

1. Compiler le moteur et le package :
   ```bash
   cd FireFox-Extension
   ./build.sh
   ```
2. Ouvrir Firefox et aller sur `about:debugging#/runtime/this-firefox`
3. Cliquer sur `Charger un module complémentaire temporaire`
4. Sélectionner `FireFox-Extension/extension/manifest.json`
5. Ouvrir l'icône de l'extension et vérifier le résultat d'analyse
6. Tester une URL ou un contenu suspect pour voir les menaces en direct

## Tester l'extension

- Vérifier que le service worker est actif dans `about:debugging`.
- Charger une page web contenant `login`, `password` ou `document.cookie` pour déclencher les hooks personnalisés.
- Ouvrir la popup pour afficher le score, les menaces et le nombre d'analyse.

## Prototype Python

Un moteur d'analyse parallèle est disponible dans `FireFox-Extension/python/secureweb_analyzer.py`.
Ce prototype permet de tester les règles d'analyse hors navigateur, mais l'extension Firefox elle-même utilise toujours JavaScript pour l'interface et l'intégration WebExtension.

## Licence

Le projet est livré avec la licence indiquée dans `FireFox-Extension/LICENSE.txt`.
