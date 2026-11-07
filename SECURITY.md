# Politique de sécurité

## Signaler une faille

Ne publiez **pas** la faille dans une issue publique.
Écrivez à **contact@justpita.ovh** en indiquant :

- la version concernée (voir `manifest.json`) ;
- les étapes pour reproduire le problème ;
- l'impact que vous constatez (fuite de clés, contournement du verrouillage…).

Nous accuserons réception dès que possible et vous tiendrons informé de la correction.
Merci de nous laisser un délai raisonnable avant toute divulgation publique.

## Modèle de sécurité

- Les clés sont chiffrées en AES-256-GCM. La clé de chiffrement est dérivée du mot de passe maître avec PBKDF2-SHA256 (600 000 itérations, sel aléatoire).
- Le manifest ne demande que la permission `storage`, et la politique de sécurité de contenu interdit toute connexion réseau (`connect-src 'none'`).
- Pendant le déverrouillage, la clé est conservée dans `chrome.storage.session` (mémoire du navigateur, jamais écrite sur le disque) jusqu'au verrouillage ou à l'expiration choisie.

## Limites connues

- Ce projet n'a **pas été audité** par un tiers.
- Un mot de passe maître faible reste vulnérable à une attaque par force brute sur le coffre volé.
- Un logiciel malveillant exécuté sur la machine pendant que le coffre est déverrouillé peut lire les codes affichés.
- Les clés exportées par Google Authenticator (QR d'export) sont en clair : supprimez toute capture ou photo après usage.
