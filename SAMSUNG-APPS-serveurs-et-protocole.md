# Samsung Apps sur bada 2.0 — Fonctionnement des serveurs, protocole et banc local BadaRevival

> Document de synthèse **complet** sur le fonctionnement des serveurs Samsung Apps et du
> protocole utilisé par le client bada 2.0 : reverse-engineering de `Kona.exe` / `BDAgent.exe`,
> analyse des logs réseau, reconstitution du protocole et du banc local de test.
> Référence arrêtée au **19 novembre 2026**.

---

## 1. Identité du client et contexte firmware

| Élément | Valeur |
|---|---|
| Modèle | **GT-S5380** (Samsung Wave Y) |
| Opérateur / CSC | **BOG** (Bouygues), `mcc=208`, `mnc=20` |
| Firmware | **S5380AGLJ1**, 2012-10-17, **bada 2.0** |
| User-Agent (toutes les requêtes) | `Mozilla/5.0 (SAMSUNG; SAMSUNG-GT-S5380-BOUYGUES/S5380AGLJ1; U; Bada/2.0; fr-fr) AppleWebKit/534.20 (KHTML, like Gecko) Dolfin/3.0 Mobile HVGA SMM-MMS/1.2.0 OPN-B` |
| `systemId` de l'enveloppe | `0` |

Firmware stock officiel de référence :
`https://www.sammobile.com/samsung/gt-s5380/firmware/GT-S5380/BOG/download/S5380AGLJ1/7544/`

### 1.1 Configuration interne de BDAgent (`BDAgentConfig.ini`)

Extrait du firmware (`tmp/fw/ba/Res/BDAgentConfig.ini`, 218 octets), identique dans
`tmp/fw/fs/Osp/Applications/36cbr89p8t/Res/` :

```ini
#BDAgentConfigSection
BDAgentC0=0
BDAgentC1=/Home/Share/Icon/
BDAgentC2=/Home/Share/Upgrade/
BDAgentC3=SN100
BDAgentC4=http://zirconia.samsungapps.com/normalAppRIRequest.as
BDAgentC5=0
BDAgentC6=0
BDAgentC7=0
```

**Point critique** : `BDAgentC6` vaut **0 dans le firmware usine**, mais une valeur de `1`
(constatée lors des essais) active l'exigence de licence signée Samsung. Cette valeur **n'est pas
modifiable par le réseau**. C'est la raison pour laquelle la voie « installation normale avec
licence » est fermée, et pour laquelle la voie de l'auto-mise à jour a été étudiée (§ 6.3).

---

## 2. Architecture côté client : ce qui parle aux serveurs

### 2.1 `Kona.exe` — l'application Samsung Apps

Binaire bada 2.0 extrait (`extract/Kona.exe`, symboles dans `extract/konastr.txt` et
`extract/konasym.txt`). C'est le client de boutique : écrans, requêtes, parsing XML.

Fonctions et adresses mises en évidence :

| Adresse | Symbole / rôle |
|---|---|
| `0x3140c0` | `CKonaXmlAttrPicker::GetXmlParamTable` — **table des paramètres** par fonction (source de `store/params.py` et `tools/_params.txt`) |
| `0x27e760` | `CKonaNetHttpParamDoc` — choisit l'hôte selon la configuration (staging / mini / freeStore / doc) |
| — | `CKonaXmlParser` — **6 éléments seulement** : `SamsungProtocol`, `request`, `response`, `errorString`, `list`, `value`. Tout autre nom d'élément est ignoré. |
| — | `CKonaNetHttpConnection::SendHttpRequest` — passe l'URL **telle quelle** à `HttpSession::Construct` / `HttpRequest::SetUri` (n'ajoute aucun chemin) |
| — | `KonaViewManager::FillCheckAppUpgradeForm` — compare `disclaimerVer` via `KonaViewUtil::CompareVersionString` ; si la réponse est supérieure → `SetDisclaimerVersion("", true)` → popup `0x7d3` |
| — | `KonaSplashForm::FillCountrySearchForm` — `SetFreeStore(resp[0x74] ^ 1)`, empile l'écran `0x408`, envoie la `5060` |
| — | `KonaDisclaimerForm::FillForm` — pose le texte de la `5060` dans un TextBox natif, puis 3 boutons `OpenUrlInBrowser` |
| — | `KonaAccountRegisterForm`, `KonaTermsForm`, `KonaMyPageListForm`, `KonaUpgradeForm`, `KonaAboutForm`, `KonaSettingsForm`, … |

IDs d'applications préinstallées envoyés dans la requête `2301` (`preloadApp`) :
```
36cbr89p8t@0.1.3   (BDAgent)
404276ukne@1.0.0
53mdtiq3d1@0.0.0
8d7uw8z551@0.1.3   (Kona = Samsung Apps)
g4e65vo3ik@1.0.0
kfdoqs63to@1.0.1
rcz4775900@0.0.1
um3clj6k6j@1.0.0
0x1000223c@0.03
0x1000223d@0.01
0x1000223e@0.01
```
(`preloadCount=13`). L'application « Exploration » `559t46hurs` est celle que nous avons
servie sous le nom `Kona.oap` lors de la tentative d'auto-mise à jour (§ 6.4) — le paquet est
encore dans `store/apps/559t46hurs.app` (543 802 octets).

### 2.2 `BDAgent.exe` — l'agent de fond

Agent système (1 147 100 octets), tourne en permanence, gère le téléchargement, le DRM et
l'auto-mise à jour. Chaîne de fonctions relevée (`drm_strings.txt`, `sec_strings.txt`) :

| Adresse | Symbole / rôle |
|---|---|
| `0x66800` | `BDAgentSelfUpdateMgr::UpgradeKona()` — installe `/Home/Share/Upgrade/Kona.oap` via `PackageManager` **sans contrôle DRM** |
| `0x66898` | dans `UpgradeKona` : abandon **si `AppManager::IsRunning("8d7uw8z551")`** est vrai |
| `0x68300` | `BDAgentSelfUpdateMgr::RequestComplete` — séquence des deux paquets de self-update |
| `0xea88e` (.rodata) | balises attestées de la réponse RI : `<SID length>`, `<CID length>`, `<RIURL length>` |
| `0xe9a34` | `BDAgentAppInstallMgr::InstallApplication(...)` (ne prend **pas** d'appId : lit le manifeste du paquet) |
| `0xea2f8` | `BDAgentDrmDownMgr::GetDRMContentsInfo(...)` |
| `0xea42c` | `BDAgentDrmDownMgr::ProcessDrmProtect(...)` |
| `0xeadc9` | `[BDAgentDRM] Now call GenerateDrmLicenseRequest()` |
| — | `CBDAgentConfiguration::GetFromRegistry`, `RestoreAllConfig`, `TrimAllInitialStringValue` |
| — | `BDAgentUna::CalcNextTime`, `SetUnaWakeupTime` (réveils planifiés) |
| — | `BDCommReqParamUpgrade::SetBDAgentContentSizeEl...` (dans `Kona.exe`) |

### 2.3 Autres composants

- **mosp / IdentityManager** (bada 1.2 analysé, même famille que le mosp 2.0 du téléphone) :
  endpoints `/security/*`, `msecIdentityManagerImpl.c`, `__IdentityManagerImpl_saveServerTime`,
  `__IdentityManagerImpl_saveCredentialResult`, `__IdentityManagerSpi_getValueFromXmlRoot`.
- **Dolfin 3.0** : navigateur intégré, ouvre les 3 boutons de l'écran « Conditions générales ».
- **Gestionnaire de téléchargement bada** : protocole binaire sur `/bd` (non élucidé ; journalisé).

---

## 3. Le protocole `SamsungProtocol`

### 3.1 Transport

- **HTTP clair**, `POST /ods.as`, `Content-Type: text/xml`, HTTP/1.1 avec `Connection: keep-alive`.
- Une connexion TCP porte généralement **une seule requête** puis `FIN` (les RST observés
  après le FIN sont le comportement du client bada, pas une erreur du serveur).
- Les pages web et vignettes sont en HTTP sur les hôtes `www.samsungapps.com`,
  `static.bada.com`, `img.samsungapps.com`.
- Les documents `2306` (`checkAppUpgrade`) et `5060` (`termInformation`) passent par
  **`www.ospserver.net` sur le port 443** (§ 7).

### 3.2 Enveloppe XML

Requête (exemple réel, `2301`) :
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<SamsungProtocol version="0.9" lang="EN">
  <request id="2301" name="getUpgradeNKillCount" transactionId="2">
    <param name="postloadCount">0</param>
    <param name="imei">…</param>
    <param name="preloadApp">36cbr89p8t@0.1.3||…</param>
    <param name="preloadCount">13</param>
  </request>
</SamsungProtocol>
```

Réponse (fabriquée par `mock.py`, format établi par désassemblage) :
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<SamsungProtocol version="0.9" lang="EN" networkType="0" deviceModel="GT-S5380"
                 supportWebp="false" systemId="0">
  <response id="2309" name="getDownloadList" returnCode="0"
            startNum="1" endNum="3" totalCount="3" transactionId="3">
    <list numValue="4">
      <value name="GUID">1000000001</value>
      <value name="version">1.0.0</value>
      …
    </list>
  </response>
</SamsungProtocol>
```

Règles de format **impératives** (découvertes à force de tests) :
1. `CKonaXmlParser` ne connaît que 6 éléments ; tout le reste est ignoré.
2. Les compteurs (`totalCount`, `startNum`, `endNum`) sont des **attributs** de `<response>`.
3. **Aucun blanc** entre `<list>` et le premier `<value>` : le texte intermédiaire serait
   ajouté à la valeur du premier paramètre.
4. Chaque `<list numValue="n">` contient exactement `n` valeurs.
5. L'**ordre des `<value name="…">` est le type de paramètre** : c'est l'index dans la table
   `CKonaXmlAttrPicker::GetXmlParamTable` qui décide du rangement dans l'objet C++. Un ordre
   faux = valeurs décalées. Voir `store/params.py` (table `PARAMS`) et `tools/_params.txt`.
6. `errorString` est le seul élément d'erreur (ex. `returnCode="1" errorCode="1004"`).

### 3.3 Table des fonctions (IDs relevés dans `Kona.exe`)

`fn` = index interne, `id` = valeur de l'attribut `id`, `cnt` = nombre de paramètres attendus
(extrait de `tools/_params.txt`).

| fn | id | cnt | fn | id | cnt | fn | id | cnt |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 | 2010 | 10 | 27 | 2234 | 1 | 54 | 3140 | 3 |
| 1 | 2011 | 10 | 28 | 2235 | 27 | 55 | 3150 | 6 |
| 2 | 2030 | 27 | 29 | 2236 | 27 | 56 | 3160 | 10 |
| 3 | 2033 | 27 | 30 | 2239 | 73 | 57 | 4030 | 0 |
| 4 | 2034 | 27 | 31 | **2300** | 8 | 58 | 4040 | 0 |
| 5 | 2035 | 27 | 32 | **2301** | 3 | 59 | 4050 | 0 |
| 6 | 2036 | 27 | 33 | 2302 | 27 | 60 | 4060 | 6 |
| 7 | 2037 | 27 | 34 | **2303** | 10 | 61 | 4070 | 2 |
| 8 | 2038 | 27 | 35 | 2304 | 27 | 62 | 4080 | 0 |
| 9 | 2039 | 27 | 36 | **2306** | 22 | 63 | 4090 | 27 |
| 10 | 2080 | 73 | 37 | 2308 | 6 | 64 | 4100 | 0 |
| 11 | 2090 | 10 | 38 | **2309** | 4 | 65 | 4110 | 0 |
| 12 | 2100 | 7 | 39 | 2310 | 27 | 66 | 4120 | 0 |
| 13 | 2110 | 11 | 40 | 2320 | 6 | 67 | **5010** | 11 |
| 14 | 2140 | 27 | 41 | 2340 | 13 | 68 | **5020** | 0 |
| 15 | 2150 | 73 | 42 | **2350** | 2 | 69 | **5050** | 1 |
| 16 | 2160 | 73 | 43 | 2360 | 3 | 70 | **5060** | 2 |
| 17 | 2170 | 8 | 44 | 2237 | 6 | 71 | 5090 | 0 |
| 18 | 2180 | 13 | 45 | 2238 | 27 | 74 | **5093** | 1 |
| 19 | 2190 | 4 | 46 | 3010 | 10 | 75 | **5094** | 1 |
| 20 | 2200 | 8 | 47 | 3020 | 10 | 76 | 5095 | 0 |
| 21 | 2210 | 6 | 48 | 3021 | 0 | 77 | **5100** | 11 |
| 22 | 2220 | 2 | 49 | 3030 | 10 | 78 | categoryList | 0 |
| 23 | 2230 | 2 | 50 | **3040** | 10 | | | |
| 24 | 2231 | 8 | 51 | 3110 | 10 | | | |
| 25 | 2232 | 73 | 52 | 3120 | 3 | | | |
| 26 | 2233 | 1 | 53 | 3130 | 10 | | | |

**Paramètres des fonctions les plus importantes :**

- **2300 `countrySearchEx`** (8) : `countryURL`, `countryCode`, `freeStoreClsf`, `description`,
  `currencyUnitPrecedes`, `currencyUnitHasPenny`, `snsVal`, `currencyUnitDivision`.
- **2301 `getUpgradeNKillCount`** (3) : `UpgradeCount`, `KillCount`, `Timer`.
- **2306 `checkAppUpgrade`** (22) : `upgrade`, `contentSizeLimitation`, `freeStoreClsf`,
  `clientType`, `odcUrl`, `odcSize`, `bdUrl`, `bdSize`, `2gLimit`, `25gLimit`, `3gLimit`,
  `wifiLimit`, `licenseUrl`, `freetabClsf`, `disclaimerVer`, `snsVal`, `notificationType`,
  `odcConfigurationId`, `secureTime`, `flexibleTabClsf`, `addMobClsf`, `minPrice`.
- **2350 `getPushNotificationMessage`** (2) : `notificationMsg`, `notificationParam`.
- **2303 / 3040 `download`** (10) : `downLoadURI`, `contentsSize`, `productID`, `productName`,
  `orderID`, `successYn`, `installSize`, `paymentID`, `paymentStatusCD`,
  `paymentRequestCompleteDate`.
- **5060 `termInformation`** (2) : `value` (le texte), `disclaimerVer`.
- **5100 / 5010** (11) : compte ; **5050** (1) : `userID` ; **5093** : `realAge` ;
  **5094** : `configurationUrl`.

---

## 4. Les hôtes, le DNS et les ports

### 4.1 Hôtes interrogés par le client bada (observés dans `tmp/bench-logs/dns.log`)

| Hôte | Rôle | Redirigé vers le banc ? |
|---|---|---|
| `hub-odc.samsungapps.com` | hub ODC, requêtes `2300` au démarrage | ✅ oui |
| `fr-bou.samsungapps.com` | serveur de documents/pays Bouygues (`2350`, `2301`, `2309`, `2300`, `5060`) | ✅ oui |
| `www.samsungapps.com` | pages web « Conditions générales » (`/common/term.as`, `/common/privacy.as`) | ✅ oui |
| `static.bada.com` | texte `/contents/deviceterms/<MCC>.txt` | ✅ oui |
| `img.samsungapps.com` | vignettes produits | ✅ oui (non encore vu à l'usage) |
| `zirconia.samsungapps.com` | endpoint RI `normalAppRIRequest.as` de `BDAgentC4` | ✅ oui |
| `www.ospserver.net` | documents `2306` / `5060`, **port 443** | ✅ oui (TLS ou HTTP clair) |
| `gld.push.samsungosp.com` | push Samsung, port 5223 | ❌ non (aucun service chez nous → RST) |
| `samsungshp.vlingo.com` | reconnaissance vocale | ❌ non |
| `opt.samsungadhub.com` | publicité | ❌ non |

Cartes de référence : `tools/dns-map.txt` (PC) et
`/home/user/badarevival/tools/dns-map.txt` (Pi). Sauvegarde complète :
`/home/user/badarevival/tools/dns-map.txt.sauvegarde-avant-wipe`.

**Règle fondamentale** : ne rediriger **que** les hôtes que le banc sait réellement servir.
Un hôte redirigé sans service derrière produit un **RST immédiat**, que le client bada traduit
par « **Réseau non disponible** ». C'est pour cette raison que `gld.push…`, `vlingo` et
`samsungadhub` sont laissés au resolveur réel.

### 4.2 Choix de l'hôte par `CKonaNetHttpParamDoc` (0x27e760)

```
config[0x1c] (staging) == 0  -> GetHostAddr          (config+0x348)   <- notre cas
config[0x281] (mini mode)    -> GetStgUdcDocAddr     (config+0x2b0)
config[0x375] (freeStore)    -> GetStgFreeDocAddr    (config+0x29c)
sinon                        -> GetDocHostAddr       (config+0x48)
```

Conséquence observée : avec `staging=0`, la `2300` part vers `GetHubUrl()` (`hub-odc`) via
`HostAddr` ; `FillCountrySearchForm` fixe ensuite `HostAddr` à `countryURL`, et c'est **cette
valeur et elle seule** qui décide de l'URL de la `5060`.

---

## 5. Séquence de démarrage de Samsung Apps (enregistrée)

Log de référence : `tmp/store-1106.log` (6 nov. 2026, client bada `192.168.1.68`).

```
19:13:59  POST fr-bou.samsungapps.com /ods.as  id=2350 getPushNotificationMessage tid=1
          param: imei (masqué)                                      -> 427 octets
19:14:00  POST fr-bou.samsungapps.com /ods.as  id=2301 getUpgradeNKillCount tid=2
          params: postloadCount=0, imei, preloadApp (13 ids), preloadCount=13 -> 441 octets
19:14:00  POST fr-bou.samsungapps.com /ods.as  id=2309 getDownloadList tid=3
          params: contentType=all, alignOrder=updated, imei, imgWidth=100,
                  imgHeight=70, endNum=0, startNum=0               -> 837 octets
19:14:20  POST hub-odc.samsungapps.com /ods.as id=2300 countrySearchEx tid=1
          params: whoAmI=odc, latestCountryCode=208                 -> 681 octets
          ... puis 5060 termInformation vers www.ospserver.net:443 (HTTPS)
```

Le cycle `2350 / 2301 / 2309` se répète à chaque retour à l'accueil (19:14:25, 19:15:35,
19:15:39…). La `2300` vers `hub-odc` est l'étape qui fixe le pays et l'URL de la boutique.

`countryURL` **doit contenir le chemin `/ods.as`** : `CKonaNetHttpParamDoc` ne rajoute jamais
de chemin. Sans lui, la `5060` est refusée **localement**, avant tout socket et toute résolution
DNS (rien dans `packets.log`) → « Réseau non disponible ». Preuve : les `2350/2301/2309`
envoyées au lancement avec le `HostAddr` par défaut arrivent bien sur `/ods.as`.

---

## 6. Les mécanismes serveur mis au jour (leviers et pièges)

### 6.1 Version du disclaimer — `2306` + `5060` (popup `0x7d3`)

- `DISCLAIMER_VERSION` (défaut `9999`, variable d'environnement) est renvoyée **identiquement**
  par la `2306` (`disclaimerVer`) et la `5060` (`disclaimerVer`).
- `KonaViewManager::FillCheckAppUpgradeForm` compare cette version à celle mémorisée sur le
  téléphone (**registre, config+0x2cc**) avec `KonaViewUtil::CompareVersionString`.
- Si la réponse est **supérieure** → `SetDisclaimerVersion("", true)` → popup `0x7d3` au
  lancement suivant. La version étant vidée, `FillCountrySearchForm` empile l'écran `0x408` et
  envoie la `5060`.
- Il faut une valeur **plus grande que tout ce que le vrai serveur a pu stocker**, et **la même
  dans les deux réponses**, sinon boucle « accepter → effacer → ré-accepter ».
- Le texte affiché vient du champ `value` de la `5060`, pas du web. Les 3 boutons ouvrent :
  - `http://www.samsungapps.com/common/term.as?mcc=208`
  - `http://www.samsungapps.com/common/privacy.as?mcc=208`
  - `http://static.bada.com/contents/deviceterms/208.txt`
- `odcConfigurationId` est volontairement **vide** : `FillCheckAppUpgradeForm` ne lance
  `CKonaConfigReplacement` que si cet identifiant est non vide (`0xe4564`) ; une valeur
  différente déclencherait une `5094` et un remplacement de configuration sans rapport.

### 6.2 `freeStoreClsf` — inverseur de `2300`

- `KonaSplashForm::FillCountrySearchForm` fait `SetFreeStore(resp[0x74] ^ 1)` : la valeur est
  **inversée** avant d'être stockée dans `config+0x375`.
  - `freeStoreClsf="Y"` → `freeStore=0`
  - `freeStoreClsf="N"` → `freeStore=1`
- Nous annonçons **`Y`** (`freeStore=0`). La valeur est aussi mémorisée dans le registre
  (paramètre `0x11`) par `SetLastCountryFree` : si elle a déjà été enregistrée à 1, le chemin
  rapide du splash la reprend telle quelle et la `2300` n'est pas renvoyée (dans ce cas, vider
  les données de l'application ou effacer le paramètre `0x11` avant de relancer).

### 6.3 `upgrade=1` / auto-mise à jour BDAgent — **voie abandonnée**

Détour imaginé parce que l'installation normale passe par `ProcessDrmProtect` puis
`GetDRMContentsInfo`, qui exigent une licence signée Samsung (`BDAgentC6=1`, § 1.1).
`UpgradeKona()` installe `/Home/Share/Upgrade/Kona.oap` **sans aucun contrôle DRM**.

Séquence vérifiée dans `BDAgent.exe` :
1. `BDAgentSelfUpdateMgr::RequestComplete` (`0x68300`) : le **premier** paquet
   (`36cbr89p8t` = BDAgent.oap) terminé déclenche tout seul la demande du second
   (`8d7uw8z551`).
2. Second paquet terminé → déplacement de `/Home/App/{BDAgent,Kona}.oap` vers
   `/Home/Share/Upgrade/`, `SetUpgradeMode(true)`, fin de BDAgent.
3. Au redémarrage : `UpgradeKona` (`0x66800`) → `InstallApplication(ct=0)` sur
   `/Home/Share/Upgrade/Kona.oap`.

**Cause de l'échec du 13/11** : `UpgradeKona` abandonne **sans rien installer** si
`IsRunning("8d7uw8z551")` est vrai (`0x66898`) — Samsung Apps était ouvert pendant tout le
téléchargement. Résultat : boîte `0xff10`, application restée en « pause ». D'où le serveur
`slowdl.py` (débit 16 Ko/s, port 8080) laissait ~1 minute pour quitter l'application.

Autre piège : `InstallApplication` ne prend pas d'appId, il lit le **manifeste** du paquet.
Servir Exploration comme « Kona.oap » installe donc Exploration sous son propre appId
(`559t46hurs`), pas sous celui de Samsung Apps. La taille annoncée doit être **exacte**
(543 802 octets).

**Configuration de référence** : `UPGRADE_ENABLED = False`, `DL_RATE_KBPS = 0`,
`upgrade=N` dans `checkAppUpgrade.xml`.

### 6.4 DRM / Right Issuer (`normalAppRIRequest.as`, `ri.as`)

Après un téléchargement, `BDAgentDrmDownMgr` construit un XML (`<DRMType>`, `<sid>`, `<cid>`)
et le poste à `BDAgentC4`, c'est-à-dire
`http://zirconia.samsungapps.com/normalAppRIRequest.as`. Requête réelle capturée le
14/11/2026 à 14:10:50 (162 octets) :

```xml
<request>
  <DeviceInfo><imei>354385051123773</imei></DeviceInfo>
  <ContentInfo><DRMType>0</DRMType><sid>SN100</sid><cid>1000000001-1.3.1</cid></ContentInfo>
</request>
```

Réponse par défaut construite par `mock.py` (192 octets) :

```xml
<?xml version="1.0" encoding="UTF-8"?>
<response returnCode="0">
  <SID length="5">SN100</SID>
  <CID length="16">1000000001-1.3.1</CID>
  <RIURL length="25">http://192.168.1.21/ri.as</RIURL>
</response>
```

Puis le téléphone a posté 10 octets sur `/ri.as` (14:10:55) ; réponse par défaut
`<response returnCode="1"/>` (26 octets). Le module ECOM réel
(`DrmSdcGenerateLicenseRequest`) est **absent du firmware extrait**, donc le format exact de la
réponse de licence est inconnu. Les fichiers `store/responses/appri.xml` (demande RI) et
`ri.xml` (licence) permettent de surcharger à chaud, avec les substitutions
`{{sid}}`, `{{cid}}`, `{{url}}`, `{{drmtype}}`.

**Valeur de référence** : `appri.xml` =
`<?xml version="1.0" encoding="UTF-8"?><response returnCode="0"/>` (enveloppe neutre).

### 6.5 Compte Samsung — parcours `/security/*` (SSO / IDM)

Endpoints journalisés et servis par `mock.py` (protocole déduit du désassemblage de `mosp`) :

| Méthode / chemin | Réponse |
|---|---|
| `GET /security/sso/initialize/time` | `<response><currentServerTime><unix></currentServerTime></response>` |
| `POST /security/sso/userprofiles/authentication/emailid` | `<userAuthResponse>` avec `userID`, `plainID`, `emailID`, `deviceID`, `authToken`, `authTokenSecret`, `birthDate` |
| `GET/POST /security/sso/userprofiles/authentication/application` | `<credentialResponse><accessToken>…</accessToken><accessTokenSecret>…</accessTokenSecret></credentialResponse>` |

Le corps de la requête d'authentification contient `<loginID>`, `<password>`, `<duid>`.
Le client ne lit que `accessToken` et `accessTokenSecret`
(`__IdentityManagerImpl_saveCredentialResult`).

Parallèlement, la boutique a **son propre** parcours de compte, sans Bori/SSO :
```
5100 checkDuplication -> écran des conditions (0x40b)
5050 joinRegister     -> KonaTermsForm::FillPaymentSaveForm -> SetLoggedIn(true), SetUserId, SetAutoLogin
5010 login            -> connexion si une identité est déjà mémorisée
5020 logout, 5093 nameAuthSetting (realAge=30 -> majeur), 5094 getConfiguration
```
Aucun mot de passe n'est vérifié : tout identifiant est accepté. Les réponses sont surchargeables
via `store/responses/security_*.txt` (nom = chemin sans `/`, `/` remplacé par `_`).

### 6.6 Autres endpoints servis

- `/social/*` : création de compte appli, enregistrement de l'appareil (protocole partiellement
  connu, journalisé).
- `/bd` : protocole binaire du gestionnaire de téléchargement (inconnu, réponse vide neutre).
- `/i/*.png` : vignettes PNG 48×48 générées à la volée.
- `/dl/<fichier>.app` : paquets de `store/apps/`, avec support des requêtes `Range`
  (`206 Partial Content`, `Content-Range`, `Accept-Ranges`) — le gestionnaire bada reprend par
  morceaux.
- `/common/*`, `/t.as`, `/contents/deviceterms/*` : pages/texte des conditions générales.

---

## 7. TLS et SSLv2 (port 443)

Le Wave Y embarque **OpenSSL 0.9.8**, qui négocie encore **SSLv2**. Le téléphone ouvre ses
connexions HTTPS par un **ClientHello SSLv2 de 102 octets** commençant par `80 64 01 03 01`,
avec le cipher `01 00 80` (**RC4-128-MD5**). Python 3 / OpenSSL 3 refusent ce format : sans
mesure spécifique, la poignée de main n'aboutit jamais et Samsung Apps affiche « Réseau non
disponible ».

Solutions mises en œuvre dans `mock.py` / `store/ssl2.py` :

- `serve_tls()` écoute sur `0.0.0.0:443`, sonde les 64 premiers octets (`MSG_PEEK`) :
  - `0x16` → TLS moderne, `ctx.wrap_socket(...)` (niveau `ALL:@SECLEVEL=0`, `TLSv1` minimum) ;
  - `0x80 01 …` → **terminateur SSLv2 maison** (`ssl2.SSL2Socket`), qui envoie ServerHello,
    CLIENT-MASTER-KEY, SERVER-VERIFY, CLIENT-FINISHED, SERVER-FINISHED, puis rend la socket
    au Handler HTTP (trafic chiffré mais HTTP ordinaire) ;
  - sinon → HTTP clair, avec consommation d'un éventuel CRLF préfixe (certains clients bada
    préfixent leur requête de `\r\n`, sinon `400` sur la ligne de requête).
- Certificat : `store/ospserver.crt` / `.key`, `CN=www.ospserver.net`,
  `notBefore=Nov 7 09:39:38 2026 GMT`, `notAfter=Nov 4 09:39:38 2036 GMT`.
- Le SNI et les échecs de handshake sont journalisés.

---

## 8. Le banc local BadaRevival

### 8.1 Topologie

| Rôle | Adresse | Détail |
|---|---|---|
| Téléphone | `192.168.1.68` | cible, DHCP |
| Pi (banc) | `192.168.1.21` | `dnsprobe.py` (:53), `mock.py` (:80/:443), utilisateur `user` |
| PC Windows | `192.168.1.90` | outils d'analyse, SSH vers le Pi, `pythonw` autorisé par firewall |

Accès SSH :
```
ssh -o BatchMode=yes -o StrictHostKeyChecking=no -i C:\Users\Compt\.ssh\badarevival_ed25519 user@192.168.1.21 "…"
```

`/home/user/badarevival/` sur le Pi :
- `tools/dnsprobe.py` — serveur DNS (écoute **sur `192.168.1.21:53`**, pas sur `127.0.0.1:53`),
  relit `tools/dns-map.txt` **à chaud** à chaque requête.
- `store/mock.py` — serveur de boutique v14 (port 80 + TLS/443).
- `store/ssl2.py`, `store/params.py`, `store/responses/`, `store/apps/`.
- `logs/dns.log`, `logs/packets.log`, `logs/store.log`, …
- `store/slowdl.py` (port 8080).

### 8.2 `mock.py` v14 — routage

```
GET  /i/*, *.png                  -> PNG généré
GET  /dl/*                        -> paquet .app (Range supporté)
GET  /security/*                  -> _security (journal + fichier modifiable)
GET  /social/*                    -> _social
GET  /normalAppRIRequest.as, /rightIssueRequest.as, /ri.as -> _ri
GET  /contents/deviceterms/*      -> texte ASCII
GET  /common/*, /t.as             -> page HTML
POST /ods.as                      -> parse XML -> build_response(rid, name, tid, params)
POST /security/*                  -> _security
POST /bd*                         -> _bd (binaire, journalisé)
POST /social/*                    -> _social
POST /ri.as                       -> _ri (licence)
```

`build_response()` applique dans l'ordre : diagnostic `skip` → diagnostic `FORCE_ERROR` /
`error_on` → fichier `responses/<name>.xml` (substitutions `{{id}}`, `{{name}}`, `{{tid}}`) →
builder enregistré (`BUILDERS`) → réponse par défaut générée depuis la table des paramètres.

Variables de diagnostic (fichiers `store/skip`, `error_on`, `hang`, `close_on`) :
`FORCE_ERROR`, `DISCLAIMER_VERSION`, `FREE_STORE_CLSF`, `HANG_TIMEOUT`, `TLS_PORT`,
`TLS_CERT`, `TLS_KEY`.

Valeurs fixes notables (`VALUES`) : `countryURL=http://fr-bou.samsungapps.com/ods.as`,
`countryCode=208`, `freeStoreClsf=Y`, `upgrade=N`, `disclaimerVer=9999`,
`odcUrl=http://192.168.1.21/ods.as`, `bdUrl=http://192.168.1.21/bd`.

### 8.3 Autres outils

- `probe/server.py` — serveur de diagnostic navigateur (`/probe` écho des en-têtes),
  utilisé pour identifier l'User-Agent et les capacités du Dolfin.
- `tmp/bench-logs/capture.log`, `packets.log`, `dns.log`, `store.log` — captures réseau.
- `extract/` — `Kona.exe`, `Kona.htb`, `konastr.txt`, `konasym.txt`.
- `tmp/fw/` — filesystem/firmware partiellement extrait (dont `BDAgent.exe`, `FOsp.so.bin`,
  `Browser.so.bin`, `BDAgentConfig.ini`). **Pas un package flashable.**

---

## 9. Chronologie des tests (repères)

| Date | Événement |
|---|---|
| 28–30 oct. 2026 | Découverte DNS des hôtes Samsung ; mise en place du Pi, de `dnsprobe.py` et de `mock.py` ; premières requêtes `2350/2301/2309/2300` du téléphone. |
| 30 oct. | Identification du rôle de `www.ospserver.net` (documents `2306`/`5060`) ; ajout des hôtes web/images. |
| 31 oct. – 2 nov. | Tests TLS/HTTPS, SNI, certificat ; élargissement temporaire de la carte DNS (push/vlingo/pub) puis réduction. |
| 3 nov. | Capture TCP (`packets.log`) : vérification du format des échanges, FIN puis RST normaux. |
| 6 nov. | Log de référence `store-1106.log` : séquence complète de démarrage de Samsung Apps. |
| 10–11 nov. | Endpoint `/security/*` (SSO/IDM) identifié et implémenté. |
| 13 nov. | Étude de la voie d'auto-mise à jour (`upgrade=1`) : identification de `IsRunning("8d7uw8z551")` comme condition d'abandon de `UpgradeKona`. |
| 14 nov. | Requêtes DRM/RI capturées : `normalAppRIRequest.as` puis `/ri.as`. |

---

## 10. Annexes

### 10.1 Inventaire des fichiers utiles

| Fichier | Rôle |
|---|---|
| `SAMSUNG-APPS-serveurs-et-protocole.md` | ce document |
| `store/mock.py` | serveur Samsung Apps v14 (protocole, endpoints, RI, SSO) |
| `store/params.py` | table des paramètres par fonction (issue de `Kona.exe`) |
| `store/ssl2.py` | terminateur SSLv2 (RC4-128-MD5) |
| `store/slowdl.py` | téléchargement goutte à goutte (port 8080) |
| `store/responses/*.xml` | surcharges (`appri.xml`, `checkAppUpgrade.xml`, `countrySearchEx.xml`, …) |
| `tools/dns-map.txt`, `/home/user/badarevival/tools/dns-map.txt` | cartes DNS (PC/Pi) |
| `tools/_params.txt` | table brute des 78 fonctions (`fn`/`id`/`cnt`) |
| `probe/server.py`, `probe/www/` | sonde navigateur / UA |
| `extract/Kona.exe`, `konastr.txt`, `konasym.txt` | binaire + symboles Samsung Apps |
| `tmp/fw/` | filesystem/firmware partiel (BDAgent.exe, …) |
| `logs/store.log`, `logs/responses.log` | journaux serveurs |
| `tmp/store-1106.log`, `tmp/store-current.log` | séquences de démarrage de Samsung Apps enregistrées |
| `tmp/bench-logs/{dns,packets,capture}.log` | captures réseau du banc |
| `C:\Users\Compt\.ssh\badarevival_ed25519` | clé SSH du Pi |

### 10.2 Commandes de référence

```
# SSH banc
ssh -o BatchMode=yes -o StrictHostKeyChecking=no -i C:\Users\Compt\.ssh\badarevival_ed25519 user@192.168.1.21 "…"
```

### 10.3 Références code utiles (adresses `Kona.exe` / `BDAgent.exe`)

```
0x3140c0  CKonaXmlAttrPicker::GetXmlParamTable
0x27e760  CKonaNetHttpParamDoc
0x66800   BDAgentSelfUpdateMgr::UpgradeKona
0x66898   -> IsRunning("8d7uw8z551") : abandon sans installer
0x68300   BDAgentSelfUpdateMgr::RequestComplete
0xe4564   odcConfigurationId non vide -> CKonaConfigReplacement
0xea88e   <SID length>/<CID length>/<RIURL length> (rodata BDAgent)
0xe9a34   BDAgentAppInstallMgr::InstallApplication
0xea2f8   BDAgentDrmDownMgr::GetDRMContentsInfo
0xea42c   BDAgentDrmDownMgr::ProcessDrmProtect
```

### 10.4 Écrans / constantes bada

```
0x408  ecran countrySearch (declenche 5060)
0x40b  formulaire conditions (checkDuplication)
0x7d3  popup disclaimer (action 0x1b65)
0xff10 boite Telegramme d'installation (upgrade)
```

---

*Fin du document — référence technique sur le fonctionnement des serveurs Samsung Apps,
du protocole `SamsungProtocol` et du banc BadaRevival.*
