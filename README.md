# x509-parser

Une petite librairie TypeScript pour parser, simplifier et afficher des certificats X.509 (PEM ou DER).

Supporte Node.js (nativement) / Web (partiellement avec adaptation)

---

## Installation

```bash
npm install x509-parser
```

ou

```bash
yarn add x509-parser
```

---

## Fonctions principales

### 1. Charger un certificat

```ts
import { loadX509FromBufferSync } from "x509-parser";

const buffer = fs.readFileSync("certificat.pem");
const cert = loadX509FromBufferSync(buffer);
```

- Supporte **PEM** et **DER**.
- Détecte automatiquement le format.

### 2. Simplifier un certificat

```ts
import { simplifyX509Certificate } from "x509-parser";

const simpleCert = simplifyX509Certificate(cert);
console.log(simpleCert);
```

- Donne un objet propre, simple, directement exploitable.

### 3. Charger plusieurs certificats

```ts
import { loadX509AllFromBufferSync, simplifyX509All } from "x509-parser";

const buffer = fs.readFileSync("certs-chain.pem");
const certs = loadX509AllFromBufferSync(buffer);
const simpleCerts = simplifyX509All(certs);
```

- Pratique pour les **chaînes** de certificats.

### 4. Formatter / Afficher proprement

```ts
import { formatSimplifiedX509 } from "x509-parser";

console.log(formatSimplifiedX509(simpleCert));
```

- Génère une sortie texte lisible.

Ou en JSON :

```ts
import { formatSimplifiedX509AllAsJSON } from "x509-parser";

console.log(formatSimplifiedX509AllAsJSON(simpleCerts));
```

---

## Fonctions exportées

| Fonction                        | Description                                          |
| ------------------------------- | ---------------------------------------------------- |
| `loadX509FromBufferSync`        | Charge un certificat unique (PEM ou DER)             |
| `loadX509AllFromBufferSync`     | Charge plusieurs certificats trouvés dans un fichier |
| `simplifyX509Certificate`       | Simplifie un certificat brut                         |
| `simplifyX509All`               | Simplifie plusieurs certificats                      |
| `printSimplifiedX509`           | Affiche joli en console un certificat                |
| `printSimplifiedX509All`        | Affiche une liste de certificats                     |
| `formatSimplifiedX509`          | Formatte en texte structuré                          |
| `formatSimplifiedX509AllAsJSON` | Formatte une liste en JSON                           |

---

## Types principaux

- `X509Certificate`
- `SimplifiedX509Certificate`

---

## Remarques

- Le parsing ASN.1 est **custom** (pas de dépendance externe !)
- Beaucoup d'extensions X.509 sont supportées (SubjectAltName, KeyUsage, BasicConstraints, etc.)
- Dates sont retournées en objets `Date` natifs JS.

---

## Limitations

- Parsing ASN.1 simplifié.
- Certaines extensions complexes peuvent être renvoyées sous forme de `hex` brut si non reconnues.

---

## Licence

MIT License

---

> Projet minimal, propre, sans dépendances lourdes.

---

**Auteur : Gwenael** 🚀
