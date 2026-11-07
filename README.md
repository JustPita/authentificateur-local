# Authentificateur local

Extension Opera GX / Chromium (Manifest V3) qui génère des codes TOTP, comme Google Authenticator.
Elle fonctionne **100 % hors ligne** et chiffre vos clés avec un mot de passe maître.

> ⚠️ Projet non audité. Gardez toujours une sauvegarde de vos clés (voir plus bas).

## Fonctions

- Codes TOTP (SHA-1, SHA-256, SHA-512 ; 6 ou 8 chiffres ; période libre) avec compte à rebours, copie d'un clic.
- Ajout par lien `otpauth://`, par saisie manuelle, par image de QR code ou **par webcam**.
- Import d'un export Google Authenticator (`otpauth-migration://`).
- Sauvegarde et restauration chiffrées.
- Verrouillage automatique réglable.

## Installation

1. Téléchargez ou clonez ce dépôt.
2. Ouvrez `opera://extensions` (ou `chrome://extensions`) et activez le **Mode développeur**.
3. Cliquez sur **Charger l'extension non empaquetée** et choisissez le dossier du dépôt.

### Depuis une release

Téléchargez `authentificateur-local-<version>.zip` dans les *Releases* du dépôt, décompressez-le, puis chargez le dossier comme ci-dessus.

## Migrer depuis Google Authenticator

1. Dans Google Authenticator : menu → **Transférer des comptes** → **Exporter des comptes**.
2. Dans l'extension : **＋** → **📷 Scanner un QR avec la webcam**, puis présentez le QR.
   L'écran d'export bloque les captures d'écran : la webcam ou une photo prise avec un autre appareil est donc nécessaire.
3. Comparez les codes des deux applications avant de supprimer l'ancienne.

## Sécurité

- AES-256-GCM, clé dérivée par PBKDF2-SHA256 (600 000 itérations).
- Seule permission demandée : `storage`. Aucune connexion réseau possible (CSP `connect-src 'none'`).
- Le mot de passe maître n'est **pas récupérable**.

Détails, limites et signalement d'une faille : voir [SECURITY.md](SECURITY.md).

## Développement

```bash
npm test         # vecteurs de test RFC 6238, otpauth, migration Google
npm run icons    # régénère icons/*.png
npm run package  # crée dist/authentificateur-local-<version>.zip (extension seule)
```

### Publier une version

1. Changez `version` dans `manifest.json` **et** `package.json` (elles doivent être identiques).
2. Créez et poussez le tag : `git tag v1.0.1 && git push origin v1.0.1`.
3. GitHub Actions lance les tests et joint le zip à la release.

Le même zip peut être envoyé sur Opera Add-ons ou le Chrome Web Store. Ils demandent une description, des captures d'écran et l'URL de [PRIVACY.md](PRIVACY.md) ; la revue peut prendre du temps, car l'extension manipule des secrets.

Aucune dépendance de build. Fichiers principaux : `lib.js` (TOTP et imports), `vault.js` (chiffrement), `popup.js` (interface), `cam.js` (webcam).

## Licences

Code du projet : [MIT](LICENSE). Composant tiers : jsQR (Apache-2.0), voir [THIRD_PARTY.md](THIRD_PARTY.md).
