# Rapport d'audit et version améliorée — IJAI31343

Périmètre : dépôt `IJAI31343-Bayesian-ECC-EOSIO-IoT` (code, données archivées, modèles Scyther, contrats EOSIO, firmwares ESP8266/ESP32).
Méthode : lecture complète du code, recalcul des chiffres publiés à partir des données archivées, exécution des scripts publiés **sans modification**, puis correctifs minimaux avec tests.

## 1. Ce qui a été vérifié (et qui est correct)

| Vérification | Résultat |
|---|---|
| 39 empreintes d'attestation EOSIO (18 ESP8266 + 21 ESP32) recalculées depuis les journaux d'événements | 39/39 identiques |
| Tableau Stage 6 vs `stage6_statistical_summary.json` | identique |
| Chiffres du manuscrit : 522,67 ms (X25519), 716,44 ms (P-256), écart 27,05 % | recalculés, exacts |
| Rejeu Stage 4 (script publié) vs CSV archivé | écart maximal 0 |
| Intervalle 83,94 s → 51,71 s (−38,40 %) | recalculé, exact |
| Scénarios synthétiques (12 graines × 6 scénarios), script publié relancé | agrégats identiques (écart 0) |
| Manifestes SHA-256 (dépôt et Scyther) | conformes |
| Suites de tests d'origine | passent, une fois les chemins corrigés (voir 2.1) |

Les nombres du papier sont donc **reproductibles à partir des données archivées**. Rien n'indique de chiffre erroné.

## 2. Problèmes trouvés dans le code

### 2.1 Reproductibilité (bloquant pour un relecteur)
- Les tests de boucle locale cherchaient `04_Security_Verification/Pi_Gateway/gateway_epoch.py`, chemin absent du dépôt : ils échouaient tels quels. Corrigé par un mapping explicite vers `01_ECC_Key_Renewal/Gateway/*_stage7.py`.
- La passerelle ne pouvait pas importer `epoch_protocol` ni `intelligent_key_renewal` depuis l'arborescence publiée. Corrigé (amorçage de `sys.path` + repli d'import).
- Les scripts d'analyse supposent une arborescence `Revision_31343/...` qui n'existe pas. `tools/verify_release.py` recrée cette disposition dans un dossier temporaire et lance les scripts d'origine.

### 2.2 Sécurité de la passerelle
- **Inondation de fausses alarmes (démontré).** Chaque message `/data` invalide était compté comme observation de risque. 50 messages forgés font passer l'intervalle de 75,4 s à 28,4 s : un attaquant sans clé peut forcer des renouvellements fréquents (déni de service énergétique côté capteur). Correctif : `SuspiciousEventLimiter` (par défaut 10 événements / 60 s, désactivable). Avec le plafond : 40,1 s, 10 comptés, 40 ignorés. Le comportement par défaut du contrôleur reste identique à celui du papier (test de régression sur le CSV archivé).
- Le MAC est maintenant vérifié **avant** la mise à jour du compteur.
- Champs hexadécimaux validés strictement (regex), plafond de poignées de main simultanées par adresse IP.
- Bannière « STAGE7 LAB » : cette passerelle est un prototype de laboratoire, pas un service de production.

### 2.3 Estimateur bayésien
- Le quantile postérieur par Monte-Carlo (1024 tirages) ajoute un bruit et une dépendance à la graine. Option `posterior_method="exact"` (bêta incomplète régularisée), **non activée par défaut** pour conserver les résultats publiés.
- Option `decay<1` (oubli exponentiel), exigeant la méthode exacte.

### 2.4 Client EOSIO JS
- Clés lues dans un `config.json` en clair ; variable `privateKey` déclarée mais jamais utilisée ; `authenticate()` jamais attendu ni erreurs propagées ; `digest('hex')` ne renvoie pas une chaîne hexadécimale avec `blake2s-js` (utiliser `hexDigest()`).
- Réécrit : secrets via variables d'environnement, code de sortie non nul en cas d'échec. `config.json` ajouté au `.gitignore`. **Non exécuté** : pas d'accès réseau pour installer `eosjs`, seule la syntaxe a été vérifiée.

### 2.5 Hygiène
- `requirements.txt` ajouté (seule dépendance : `cryptography`).
- `SHA256SUMS.txt` et `PROVENANCE_PUBLIC.csv` régénérés.

## 3. Évaluation de l'oubli exponentiel (scénarios synthétiques des auteurs, mêmes graines)

Brier moyen (plus bas = mieux) ; intervalle moyen en secondes.

| Scénario | Cumulatif (publié) | Fenêtre 20 | Oubli 0,95 | Oubli 0,90 |
|---|---|---|---|---|
| bénin | 0,0141 / 96,3 s | 0,0143 / 88,9 | 0,0142 / 87,9 | 0,0144 / 83,8 |
| rafale de preuves invalides | 0,0984 | 0,0998 | 0,0951 | 0,0921 |
| attaque puis récupération | 0,1845 | 0,1457 | 0,1567 | 0,1574 |
| inondation de fausses alarmes | 0,2389 | 0,1537 | 0,1858 | 0,1850 |

Récupération après attaque (pas pour revenir ≥ 70 s) : cumulatif 60 (jamais), fenêtre 20 : 15,5, oubli 0,95 : 28,4, oubli 0,90 : 13,4.

**Lecture honnête.** L'estimateur cumulatif publié récupère très mal après une attaque : l'historique s'accumule et l'intervalle reste court. L'oubli améliore l'erreur de prédiction et la récupération, au prix d'intervalles un peu plus courts en régime bénin (96 s → 84–88 s, donc un peu plus d'énergie). **Ces scénarios sont synthétiques et conçus par les auteurs** : ils montrent que le mécanisme fonctionne, pas que les performances se transfèrent à du trafic réel. Contre l'inondation de fausses alarmes, le vrai remède est le limiteur (2.2), pas l'oubli. Je ne recommande pas de changer l'estimateur des résultats publiés sans les refaire ; l'option est fournie, désactivée par défaut.

## 4. Limites qui subsistent (à dire dans le papier)

1. **Pas de chiffrement authentifié du canal de données** : HMAC seul. La confidentialité des données applicatives n'est pas assurée par ce protocole.
2. **Secret avancé (forward secrecy)** : les modèles Scyther abstraient l'ECDH ; ils ne prouvent donc pas cette propriété. Un modèle Tamarin ou ProVerif serait nécessaire pour l'affirmer.
3. **PSK statique** : sa compromission permet l'usurpation de futures sessions ; les clés éphémères n'y changent rien pour l'authentification.
4. **État d'époque en RAM** (`lastConfirmedEpoch` côté ESP8266) : après redémarrage, un rejeu d'ancien état n'est pas détecté par le firmware.
5. **T_b = 600 s** est un scénario supposé, pas une mesure ; les poids λ, T0, T_min, T_max ne sont pas calibrés sur des données réelles.
6. **Journaux séries bruts absents** : les temps du Stage 6 ne sont vérifiables que depuis le résumé archivé, pas recalculables.
7. **Blockchain** : l'attestation est rétrospective (hachage d'événements), sur une chaîne de développement mono-nœud. Elle ne garantit ni disponibilité ni consensus réel.
8. Les firmwares n'ont **pas été compilés ni exécutés** ici ; aucun test matériel.

## 5. Utilisation

```
python tools/verify_release.py          # vérification complète (~16 s)
python tools/verify_release.py --quick  # sans relance des scénarios synthétiques
python 02_Bayesian_AI/Reproduction/evaluate_discounted_estimator.py
```
Variables d'environnement de la passerelle : `IJAI_MAX_SUSPICIOUS_PER_WINDOW` (défaut 10 ; 0 = comportement d'origine), `IJAI_SUSPICIOUS_WINDOW_SECONDS` (défaut 60), `IJAI_MAX_HANDSHAKES_PER_IP` (défaut 4).

## 6. Ajouts liés à la révision du manuscrit

- `02_Bayesian_AI/Reproduction/tb_sensitivity.py` : sensibilité à T_b (100–1200 s) sur les 8 640 observations synthétiques. T_b ne limite l'intervalle que s'il est inférieur à 120/0,7 ≈ 171 s ; il n'y a de rejet que si 0,7·T_b < T_min, soit T_b < 14,3 s.
- `02_Bayesian_AI/Reproduction/forged_alarm_flood_demo.py` : 50 fausses alarmes, intervalle 76,4 → 28,2 s sans limiteur, 76,4 → 39,4 s avec (10 comptées, 40 ignorées). Simulation au niveau du contrôleur ; le comportement de la passerelle est couvert par `test_gateway_hardening.py`.
- `tools/verify_release.py` contrôle désormais ces chiffres.
- `02_Bayesian_AI/Reproduction/ewma_baseline_comparison.py` : ajoute deux moyennes mobiles exponentielles (α = 0,05 et 0,10) aux prédicteurs publiés. Les prédicteurs déjà publiés sont retrouvés (écart 5·10⁻⁶). **Résultat défavorable à l'estimateur cumulatif** : EWMA a l'erreur de Brier la plus basse dans 5 scénarios sur 6 (α = 0,10 dans 4), le cumulatif seulement dans le scénario bénin. Le manuscrit le dit.
- `tb_sensitivity_scipy_crosscheck.py` et `forged_alarm_limiter.py` (+ CSV/JSON, `README_REPRODUCTION.md`) : réimplémentation indépendante (SciPy, limiteur autonome) des deux analyses. Les chiffres concordent ; `verify_release.py` les compare si SciPy est installé.

## 7. Écart important : la passerelle publiée n'est pas celle des mesures matérielles

- Les firmwares ESP8266/ESP32 utilisent la transcription `IJAI31343-v2|<algorithme>|…` et le contexte HKDF `IJAI31343-SESSION-V2`, avec un champ `algorithm` (X25519 ou P-256), conformément aux équations du manuscrit.
- La passerelle du dépôt (`gateway_epoch_stage7.py`) et les tests de boucle locale utilisent `IJAI31343-v1` et `…SESSION-V1`, **sans champ de courbe**, et ne gèrent que X25519. Elle ne peut donc pas dialoguer avec les firmwares publiés.
- Les journaux du Stage 6 contiennent `algorithm` et `algorithm_name`, ce qui prouve qu'une passerelle compatible v2 a produit les mesures matérielles. **Son code source n'est pas dans le dépôt.**
- Action : retrouver et publier la passerelle Stage 6 (ou le script équivalent) utilisée avec les cartes. Le manuscrit signale déjà que les tests Stage 7 portent sur une copie instrumentée distincte et précise maintenant qu'elle est X25519 seule en transcription v1.
