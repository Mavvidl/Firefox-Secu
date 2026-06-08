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

## Sécurité

- Le code front-end évite les injections HTML en construisant les éléments DOM de façon sécurisée.
- Le manifest MV3 utilise `service_worker` et une CSP stricte.
- Les risques sont traités localement, et les données d'analyse sont conservées en local.

## Notes

- Le binaire WebAssembly est généré dans `extension/lib/` lors du build.
- Le manifest demande des permissions larges car l'extension inspecte le trafic réseau pour détecter des menaces.
- La version Python est un prototype d'analyse locale, mais le runtime Firefox requiert encore le JavaScript du background/popup pour fonctionner.
