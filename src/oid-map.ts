// oid-map.ts

export const OID_MAP: Record<string, string> = {
  // === 🔹 Standard Attributes ===
  "2.5.4.3": "commonName",
  "2.5.4.4": "surname",
  "2.5.4.5": "serialNumber",
  "2.5.4.6": "countryName",
  "2.5.4.7": "localityName",
  "2.5.4.8": "stateOrProvinceName",
  "2.5.4.9": "streetAddress",
  "2.5.4.10": "organizationName",
  "2.5.4.11": "organizationalUnitName",
  "2.5.4.12": "title",
  "2.5.4.42": "givenName",
  "2.5.4.97": "organizationIdentifier",
  "1.2.840.113549.1.9.1": "emailAddress",

  // === 🔹 Signature Algorithms ===
  "1.2.840.113549.1.1.1": "rsaEncryption",
  "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
  "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
  "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
  "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
  "1.2.840.10045.2.1": "ecPublicKey",
  "1.2.840.10045.4.3.2": "ecdsaWithSHA256",
  "1.2.840.10045.4.3.3": "ecdsaWithSHA384",
  "1.2.840.10045.4.3.4": "ecdsaWithSHA512",

  // === 🔹 Public Key Algorithms ===
  "1.3.101.110": "X25519",
  "1.3.101.111": "X448",
  "1.3.101.112": "Ed25519",
  "1.3.101.113": "Ed448",

  // === 🔹 X.509 Extensions ===
  "2.5.29.14": "subjectKeyIdentifier",
  "2.5.29.15": "keyUsage",
  "2.5.29.17": "subjectAltName",
  "2.5.29.19": "basicConstraints",
  "2.5.29.31": "cRLDistributionPoints",
  "2.5.29.32": "certificatePolicies",
  "2.5.29.35": "authorityKeyIdentifier",
  "2.5.29.37": "extendedKeyUsage",
  "2.5.29.30": "nameConstraints",
  "2.5.29.36": "policyConstraints",
  "2.5.29.54": "inhibitAnyPolicy",

  // === 🔹 Extended Key Usages ===
  "1.3.6.1.5.5.7.3.1": "serverAuth",
  "1.3.6.1.5.5.7.3.2": "clientAuth",
  "1.3.6.1.5.5.7.3.3": "codeSigning",
  "1.3.6.1.5.5.7.3.4": "emailProtection",
  "1.3.6.1.5.5.7.3.8": "timeStamping",
  "1.3.6.1.5.5.7.3.9": "OCSPSigning",

  // === 🔹 Authority Info Access ===
  "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
  "1.3.6.1.5.5.7.1.3": "qcStatements",
  "1.3.6.1.5.5.7.48.1": "ocsp",
  "1.3.6.1.5.5.7.48.2": "caIssuers",
  "1.3.6.1.5.5.7.48.3": "timeStampingAuthority",

  // 🌐 CA/Browser Forum OIDs (SSL/TLS, S/MIME, Code Signing)
  "2.23.140.1.1": "CA/Browser Forum Baseline Requirements Compliance",
  "2.23.140.1.2.1": "DV SSL/TLS Certificate (Domain Validation)",
  "2.23.140.1.2.2": "OV SSL/TLS Certificate (Organization Validation)",
  "2.23.140.1.2.3": "EV SSL/TLS Certificate (Extended Validation)",
  "2.23.140.1.3": "EV S/MIME Certificate",
  "2.23.140.1.4.1": "OV S/MIME Certificate",
  "2.23.140.1.4.2": "DV S/MIME Certificate",
  "2.23.140.1.5.1.1": "EV Code Signing Certificate",
  "2.23.140.1.5.3.1": "EV TLS Web Server Authentication",

  // === 🔹 QC Statements ETSI ===
  "0.4.0.1862.1.1": "id-etsi-qcs-QcCompliance",
  "0.4.0.1862.1.4": "id-etsi-qcs-QcSSCD",
  "0.4.0.1862.1.5": "id-etsi-qcs-QcPDS",
  "0.4.0.1862.1.6": "id-etsi-qcs-QcType",
  "0.4.0.1862.1.6.1": "qct-esign",
  "0.4.0.1862.1.6.2": "qct-eseal",
  "0.4.0.1862.1.6.3": "qct-web",

  // === 🔹 RGS France ===
  "1.2.250.1.177.1.1.1": "RGS Signature (personne physique)",
  "1.2.250.1.177.1.1.2": "RGS Cachet serveur",
  "1.2.250.1.177.1.1.3": "RGS Authentification personne physique",
  "1.2.250.1.177.1.1.4": "RGS Chiffrement personne physique",
  "1.2.250.1.177.1.1.5": "RGS Authentification serveur",
  "1.2.250.1.177.2.1.1.1": "RGS Niveau faible",
  "1.2.250.1.177.2.1.1.2": "RGS Niveau substantiel",
  "1.2.250.1.177.2.1.1.3": "RGS Niveau élevé",
  "1.2.250.1.177.2.4.1.1.1": "RGS Authentification personne physique (v2)",
  "1.2.250.1.177.2.4.1.1.2": "RGS Authentification personne morale (v2)",
  "1.2.250.1.177.2.4.2.1.1": "RGS Signature personne physique (v2)",
  "1.2.250.1.177.2.4.2.1.2": "RGS Signature personne morale (v2)",
  "1.2.250.1.177.2.4.3.1.1": "RGS Chiffrement personne physique (v2)",
  "1.2.250.1.177.2.4.3.1.2": "RGS Chiffrement personne morale (v2)",

  // === 🔹 AATL (Adobe Approved Trust List) ===
  "1.2.840.113583.1.1.5": "Adobe Authentic Documents Trust",
  "1.2.840.113583.1.1.7": "Adobe Document Signing",
  "1.2.840.113583.1.1.9": "Adobe PDF Signing",
  "1.2.840.113583.1.1.8": "Adobe Certified Document Services (CDS)",

  // === 🔹 Special/Other ===
  "1.3.6.1.4.1.11129.2.4.2": "certificateTransparency",
  "1.3.6.1.5.5.7.2.1": "cpsUri",
  "1.3.6.1.5.5.7.2.2": "userNotice",
};

export function getOIDLabel(oid: string): string {
  return OID_MAP[oid] ?? `Unknown OID (${oid})`;
}


export const KeyUsageLabels: Record<number, string> = {
    0: "digitalSignature",
    1: "nonRepudiation",
    2: "keyEncipherment",
    3: "dataEncipherment",
    4: "keyAgreement",
    5: "keyCertSign",
    6: "cRLSign",
    7: "encipherOnly",
    8: "decipherOnly"
};
