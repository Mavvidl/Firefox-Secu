# Prototype Python SecureWeb Analyzer

Ce répertoire contient un prototype d'analyse de sécurité en Python.
Il réplique les mêmes règles de détection de base que le moteur Rust/Wasm.

## Utilisation

```bash
cd FireFox-Extension/python
python3 secureweb_analyzer.py --url "https://example.com/login?user=test"
```

Pour analyser du contenu HTML/JS :

```bash
python3 secureweb_analyzer.py --content-file ../example/page.html --enable-crypto --json
```

## Limitation

L'extension Firefox elle-même utilise toujours JavaScript pour la partie WebExtension `background` et `popup`.
Ce prototype Python est destiné à tester les règles d'analyse hors navigateur.
