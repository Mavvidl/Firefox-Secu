# SecureWeb Analyzer

Cette documentation couvre l'extension Firefox SecureWeb Analyzer.

## Contenu

- `extension/` : l'extension Firefox prête à être installée
- `src/rust/` : moteur de détection Rust compilé en WebAssembly
- `python/` : prototype d'analyse Python
- `build.sh` : script de compilation et packaging

## Compiler l'extension

```bash
cd FireFox-Extension
./build.sh
```

## Tester en développement

```bash
cd FireFox-Extension/extension
web-ext run
```

## Tester l'extension

1. Compiler le package :
   ```bash
   cd FireFox-Extension
   ./build.sh
   ```
2. Ouvrir Firefox et aller sur `about:debugging#/runtime/this-firefox`
3. Cliquer sur `Charger un module complémentaire temporaire`
4. Sélectionner `extension/manifest.json`
5. Naviguer vers un site de test et ouvrir la popup pour voir les alertes

## Sécurité

- Le code front-end évite les injections HTML en construisant les éléments DOM de façon sécurisée.
- Le manifest MV3 utilise `service_worker` et une CSP stricte.
- Les risques sont traités localement, et les données d'analyse sont conservées en local.
- Le moteur Rust prend désormais en charge des hooks personnalisés via `register_hook()` pour ajouter des regex de détection URL/contenu en temps réel.

## Notes

- Le binaire WebAssembly est généré dans `extension/lib/` lors du build.
- Le manifest demande des permissions larges car l'extension inspecte le trafic réseau pour détecter des menaces.
- La version Python est un prototype d'analyse locale, mais le runtime Firefox requiert encore le JavaScript du background/popup pour fonctionner.
