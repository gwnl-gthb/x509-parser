import { ASN1StructuredNode, parseASN1 } from './asn1-parser.js';
import { getOIDLabel, KeyUsageLabels } from './oid-map.js';

interface X509Field<T> {
  readonly value: T;
  readonly asn1: {
    readonly offset: number;
    readonly fullHex: string;
    readonly tag: any;
  };
}

interface X509Certificate {
  version: X509Field<number>;
  serialNumber: X509Field<string>;
  signatureAlgorithm: X509Field<{ oid: string; label: string }>;
  issuer: {
    formatted: X509Field<string>;
    fields: X509Field<{ oid: string; label: string; value: string }[]>;
  };
  validity: {
    notBefore: X509Field<Date | string>;
    notAfter: X509Field<Date | string>;
  };
  subject: {
    formatted: X509Field<string>;
    fields: X509Field<{ oid: string; label: string; value: string }[]>;
  };
  subjectPublicKeyInfo: {
    algorithm: X509Field<{ oid: string; label: string }>;
    publicKey: X509Field<string>;
  };
  extensions?: {
    extnID: X509Field<{ oid: string; label: string }>;
    critical: X509Field<boolean>;
    value: X509Field<any>;
  }[];
  signatureAlgorithmCert: X509Field<{ oid: string; label: string }>;
  signatureValue: X509Field<string>;
}


// ===========================
// Helpers Génériques
// ===========================

function getDecoded<T extends string | number | boolean | object | Date = any>(node?: ASN1StructuredNode): T | null {
    if (!node || Array.isArray(node.value)) return null;

    let decoded = node.value.decoded ?? null;

    if ((node.tag.type === "UTCTime" || node.tag.type === "GeneralizedTime") && typeof decoded === 'string') {
        return parseASN1Date(decoded) as unknown as T;
    }

    return decoded as T | null;
}

function getDecodedOrForceString<T extends string | number | boolean | object | Date = any>(node?: ASN1StructuredNode): T | null {
    if (!node || Array.isArray(node.value)) return null;
    let decoded = node.value.decoded ?? null;

	if (decoded === null && node.value.rawHex && node.value.rawHex.length > 0) {
		decoded = decodeIA5String(node);
	}


    if ((node.tag.type === "UTCTime" || node.tag.type === "GeneralizedTime") && typeof decoded === 'string') {
        return parseASN1Date(decoded) as unknown as T;
    }

    return decoded as T | null;
}



function getRawHex(node?: ASN1StructuredNode): string | null {
    if (!node || Array.isArray(node.value)) return null;
    return node.value.rawHex ?? null;
}


function makeField<T>(value: T, node: ASN1StructuredNode): X509Field<T> {
  return {
    value,
    asn1: {
      offset: node.offset,
      fullHex: node.fullHex,
      tag: node.tag
    }
  };
}

function forceDecodeString(node: ASN1StructuredNode): string {
  if (!Array.isArray(node.value) && node.value?.rawHex) {
    const hex = node.value.rawHex;
    let str = '';
    for (let i = 0; i < hex.length; i += 2) {
      str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return str;
  }
  return '';
}

// ===========================
// Fonctions Principales
// ===========================

function parseX509Certificate(asn1: ASN1StructuredNode): X509Certificate {
  if (asn1.tag.type !== 'SEQUENCE' || !Array.isArray(asn1.value)) {
    throw new Error('Invalid X.509 Certificate structure');
  }

  const [tbsCertificate, signatureAlgorithm, signatureValue] = asn1.value;
  const tbs = tbsCertificate.value as ASN1StructuredNode[];

  let idx = 0;

  let version = 1;
  if (tbs[idx].tag.class === 'CONTEXT-SPECIFIC' && tbs[idx].tag.number === 0) {
    const versionInner = (tbs[idx].value as ASN1StructuredNode[])[0];
    version = (getDecoded<number>(versionInner) ?? 0) + 1;
    idx++;
  }

  const serialNumberNode = tbs[idx++];
  const signatureNode = tbs[idx++];
  const issuerNode = tbs[idx++];
  const validityNode = tbs[idx++];
  const subjectNode = tbs[idx++];
  const subjectPublicKeyInfoNode = tbs[idx++];

  let extensions: X509Certificate["extensions"] = undefined;

  while (idx < tbs.length) {
    const optionalField = tbs[idx++];
    if (optionalField.tag.class === "CONTEXT-SPECIFIC" && optionalField.tag.number === 3) {
      const extnSeqNode = optionalField.value as ASN1StructuredNode[];
      if (extnSeqNode.length > 0 && extnSeqNode[0].tag.type === "SEQUENCE" && Array.isArray(extnSeqNode[0].value)) {
        const extnList = extnSeqNode[0].value as ASN1StructuredNode[];
        extensions = extnList.map(ext => {
          const extFields = ext.value as ASN1StructuredNode[];
          const extnIDNode = extFields[0];
          const criticalNode = extFields.length === 3 ? extFields[1] : null;
          const valueNode = extFields[extFields.length - 1];

          const oid = getDecoded<string>(extnIDNode) ?? 'Unknown';
          const critical = criticalNode ? !!getDecoded<boolean>(criticalNode) : false;
          const parsedValue = parseKnownExtension(oid, valueNode);

          return {
            extnID: makeField({ oid, label: getOIDLabel(oid) }, extnIDNode),
            critical: makeField(critical, criticalNode ?? extnIDNode),
            value: makeField(parsedValue, valueNode)
          };
        });
      }
    }
  }

  const validity = validityNode.value as ASN1StructuredNode[];
  const notBeforeNode = validity[0];
  const notAfterNode = validity[1];

  const spki = subjectPublicKeyInfoNode.value as ASN1StructuredNode[];
  const algorithmNode = spki[0];
  const publicKeyNode = spki[1];

  return {
    version: makeField(version, tbsCertificate),
    serialNumber: makeField(getRawHex(serialNumberNode) ?? '', serialNumberNode),
    signatureAlgorithm: extractOIDField(signatureNode),
    issuer: extractName(issuerNode),
    validity: {
      notBefore: makeField(getDecoded(notBeforeNode) ?? '', notBeforeNode),
      notAfter: makeField(getDecoded(notAfterNode) ?? '', notAfterNode),
    },
    subject: extractName(subjectNode),
    subjectPublicKeyInfo: {
      algorithm: extractOIDField(algorithmNode),
      publicKey: makeField(getRawHex(publicKeyNode) ?? '', publicKeyNode)
    },
    extensions,
    signatureAlgorithmCert: extractOIDField(signatureAlgorithm),
    signatureValue: makeField(getRawHex(signatureValue) ?? '', signatureValue)
  };
}

// ===========================
// Helpers parsing
// ===========================

function extractOIDField(node: ASN1StructuredNode): X509Field<{ oid: string, label: string }> {
  const seq = node.value as ASN1StructuredNode[];
  const oidNode = seq[0];
  const oid = getDecoded<string>(oidNode) ?? 'Unknown';
  return makeField({ oid, label: getOIDLabel(oid) }, oidNode);
}

function extractName(seqNode: ASN1StructuredNode): {
  formatted: X509Field<string>,
  fields: X509Field<{ oid: string; label: string; value: string }[]>
} {
  if (!Array.isArray(seqNode.value)) {
    return {
      formatted: makeField('Invalid Name', seqNode),
      fields: makeField([], seqNode),
    };
  }

  const rdns = seqNode.value as ASN1StructuredNode[];

  const parts: string[] = [];
  const fields: { oid: string; label: string; value: string }[] = [];

  for (const rdn of rdns) {
    const attrSeq = (rdn.value as ASN1StructuredNode[])[0];
    const [typeNode, valueNode] = attrSeq.value as ASN1StructuredNode[];

    const oid = getDecoded<string>(typeNode) ?? 'Unknown';
    const value = getDecodedOrForceString(valueNode) ?? 'Unknown';
    const label = getOIDLabel(oid);

    parts.push(`${label}=${value}`);
    fields.push({ oid, label, value });
  }

  return {
    formatted: makeField(parts.join(', '), seqNode),
    fields: makeField(fields, seqNode),
  };
}

function parseASN1Date(str: string): Date | string {
  try {
    if (str.length === 13 && str.endsWith('Z')) {
      const year = parseInt(str.slice(0, 2), 10);
      const fullYear = year < 50 ? 2000 + year : 1900 + year;
      const month = parseInt(str.slice(2, 4), 10) - 1;
      const day = parseInt(str.slice(4, 6), 10);
      const hour = parseInt(str.slice(6, 8), 10);
      const minute = parseInt(str.slice(8, 10), 10);
      const second = parseInt(str.slice(10, 12), 10);
      return new Date(Date.UTC(fullYear, month, day, hour, minute, second));
    } else if (str.length >= 15 && str.endsWith('Z')) {
      const year = parseInt(str.slice(0, 4), 10);
      const month = parseInt(str.slice(4, 6), 10) - 1;
      const day = parseInt(str.slice(6, 8), 10);
      const hour = parseInt(str.slice(8, 10), 10);
      const minute = parseInt(str.slice(10, 12), 10);
      const second = parseInt(str.slice(12, 14), 10);
      return new Date(Date.UTC(year, month, day, hour, minute, second));
    }
  } catch { }
  return str;
}

// ===========================
// 🎯 Extensions connues
// ===========================

function parseKnownExtension(oid: string, valueNode: ASN1StructuredNode): any {
  if (oid === '2.5.29.17') return parseSubjectAltName(valueNode);
  if (oid === '2.5.29.15') return parseKeyUsage(valueNode);
  if (oid === '2.5.29.19') return parseBasicConstraints(valueNode);
  if (oid === '2.5.29.31') return parseCRLDistributionPoints(valueNode);
  if (oid === '2.5.29.32') return parseCertificatePolicies(valueNode);
  if (oid === '2.5.29.35') return parseAuthorityKeyIdentifier(valueNode);
  if (oid === '2.5.29.37') return parseExtendedKeyUsage(valueNode);
  if (oid === '1.3.6.1.5.5.7.1.1') return parseAuthorityInfoAccess(valueNode);
  if (oid === '1.3.6.1.5.5.7.1.3') return parseQCStatements(valueNode);
  return getRawHex(valueNode) ?? '';
}

type GeneralNameType = "email" | "DNS" | "URI" | "IP" | "directoryName" | "registeredID" | "otherName" | `Unknown(${number})`;

interface GeneralName {
  type: GeneralNameType;
  value: string | any;
}
  
function parseKeyUsage(node: ASN1StructuredNode): Record<string, boolean> {
  const rawHex = getRawHex(node) ?? '';
  if (!rawHex.startsWith('03')) return {};

  const unusedBits = parseInt(rawHex.slice(4, 6), 16);
  const bitsHex = rawHex.slice(6);
  
  const bitsBinary = parseInt(bitsHex, 16).toString(2).padStart(bitsHex.length * 4, '0');
  const meaningfulBits = bitsBinary.substring(0, bitsBinary.length - unusedBits);

  const usage: Record<string, boolean> = {};
  for (const [bitStr, label] of Object.entries(KeyUsageLabels)) {
    const bit = parseInt(bitStr, 10);
    usage[label] = meaningfulBits[bit] === '1';
  }

  return usage;
}

function parseBasicConstraints(node: ASN1StructuredNode): { cA: boolean; pathLenConstraint?: number } {
  const seq = Array.isArray(node.value) && node.value.length > 0 && Array.isArray(node.value[0]?.value)
    ? (node.value[0].value as ASN1StructuredNode[])
    : [];

  const result: any = {};
  if (seq.length > 0) result.cA = !!getDecoded<boolean>(seq[0]);
  if (seq.length > 1) result.pathLenConstraint = getDecoded<number>(seq[1]) ?? undefined;
  return result;
}

interface QCStatement {
    statementId: { oid: string; label: string };
    statementInfo?: any;
}

function parseQCStatements(extensionNode: ASN1StructuredNode): QCStatement[] {
    if (!extensionNode) return [];

    const rawHex = getRawHex(extensionNode);
    if (!rawHex) return [];

    const buffer = hexToArrayBuffer(rawHex);

    const parsed = parseASN1(buffer, { parseAll: true });
    if (!parsed.result || !Array.isArray(parsed.result)) {
        return [];
    }

	const topSeq = Array.isArray(parsed.result) ? parsed.result.find(n => n.tag.type === "SEQUENCE") : null;
	if (!topSeq || !Array.isArray(topSeq.value)) return [];

    const statements = topSeq.value as ASN1StructuredNode[];

    return statements.map(statement => parseSingleQCStatement(statement));
}

function parseSingleQCStatement(node: ASN1StructuredNode): QCStatement {
    const fields = node.value as ASN1StructuredNode[];
    if (!fields || fields.length === 0) {
        return { statementId: { oid: 'Unknown', label: 'Unknown' } };
    }

    const statementIdNode = fields[0];
    const statementId = getDecoded<string>(statementIdNode) ?? 'Unknown';
    const label = getOIDLabel(statementId);

    let statementInfo: any = undefined;

    if (fields.length > 1) {
        const infoNode = fields[1];

        if (statementId === "0.4.0.1862.1.5") {
            // 🛠️ Spécial pour id-etsi-qcs-QcPDS
            statementInfo = parseQcPDS(infoNode);
        } else if (statementId === "0.4.0.1862.1.6") {
            // 🛠️ Pour id-etsi-qcs-QcType (liste d'OIDs)
            statementInfo = parseQcType(infoNode);
        } else if (infoNode.tag.type === "SEQUENCE" && Array.isArray(infoNode.value)) {
            // 🧠 Récursif générique
            statementInfo = (infoNode.value as ASN1StructuredNode[]).map(child => parseAnyASN1(child));
        } else {
            statementInfo = parseAnyASN1(infoNode);
        }
    }

    return {
        statementId: { oid: statementId, label },
        statementInfo
    };
}

function parseQcType(node: ASN1StructuredNode): { oids: { oid: string; label: string }[] } {
    if (!Array.isArray(node.value)) {
        return { oids: [] };
    }

    const entries = node.value as ASN1StructuredNode[];
    const oids: { oid: string; label: string }[] = [];

    for (const entry of entries) {
        const oid = getDecoded<string>(entry) ?? '';
        if (oid) {
            oids.push({
                oid,
                label: getOIDLabel(oid)
            });
        }
    }

    return { oids };
}

function parseAnyASN1(node: ASN1StructuredNode): any {
    if (node.tag.type === "SEQUENCE" && Array.isArray(node.value)) {
        return (node.value as ASN1StructuredNode[]).map(child => parseAnyASN1(child));
    }
    if (!Array.isArray(node.value)) {
        return getDecodedOrForceString(node);
    }
    return null;
}

function parseQcPDS(node: ASN1StructuredNode): any[] {
    if (!Array.isArray(node.value)) return [];

    const entries = node.value as ASN1StructuredNode[];
    const result: any[] = [];

    for (const entry of entries) {
        if (!Array.isArray(entry.value)) continue;

        const elements = entry.value as ASN1StructuredNode[];

        const urlNode = elements.find(el => el.tag.type === "IA5String");
        const languageNode = elements.find(el => el.tag.type === "PrintableString");

		    const url = urlNode ? getDecodedOrForceString(urlNode) : null;
        const language = languageNode ? getDecoded<string>(languageNode) ?? null : null;

        if (url) {
            result.push({
                url,
                language
            });
        }
    }

    return result;
}

function decodeIA5String(node: ASN1StructuredNode): string {
    if (Array.isArray(node.value) || !node.value.rawHex) return '';
    const hex = node.value.rawHex;
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return new TextDecoder("ascii").decode(bytes);
}

function hexToArrayBuffer(hex: string): ArrayBuffer {
    if (hex.length % 2 !== 0) throw new Error("Invalid hex string");
    const buffer = new Uint8Array(hex.length / 2);
    for (let i = 0; i < buffer.length; i++) {
        buffer[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return buffer.buffer;
}

interface PolicyInformation {
  policyId: { oid: string; label: string };
  qualifiers?: { policyQualifierId: { oid: string; label: string }, qualifier: string }[];
}

interface CertificatePolicies {
  policies: PolicyInformation[];
}

function parseCertificatePolicies(node: ASN1StructuredNode): CertificatePolicies {
  const result: CertificatePolicies = { policies: [] };

  if (!node) return result;

  const rawHex = getRawHex(node);
  if (!rawHex) return result;

  const buffer = hexToArrayBuffer(rawHex);

  const parsed = parseASN1(buffer, { parseAll: true });
  if (!parsed.result || !Array.isArray(parsed.result)) {
    return result;
  }

  const topSeq = parsed.result.find(n => n.tag.type === "SEQUENCE");
  if (!topSeq || !Array.isArray(topSeq.value)) return result;

  const policies = topSeq.value as ASN1StructuredNode[];

  for (const policyNode of policies) {
    if (!Array.isArray(policyNode.value)) continue;

    const fields = policyNode.value as ASN1StructuredNode[];
    const policyIdNode = fields[0];
    const policyId = getDecoded<string>(policyIdNode) ?? 'Unknown';
    const policyLabel = getOIDLabel(policyId);

    const policyInfo: any = {
      policyId: {
        oid: policyId,
        label: policyLabel
      }
    };

    if (fields.length > 1) {
      const qualifiersNode = fields[1];
      if (Array.isArray(qualifiersNode.value)) {
        const qualifiers = qualifiersNode.value as ASN1StructuredNode[];
        policyInfo.qualifiers = qualifiers.map(q => {
          if (!Array.isArray(q.value)) return null;
          const [qualifierIdNode, qualifierValueNode] = q.value as ASN1StructuredNode[];
          const qualifierId = getDecoded<string>(qualifierIdNode) ?? 'Unknown';
          const qualifierLabel = getOIDLabel(qualifierId);

          let qualifierText = getDecoded<string>(qualifierValueNode) ?? '';

          if (!qualifierText && !Array.isArray(qualifierValueNode.value) && qualifierValueNode.value?.rawHex) {
            qualifierText = hexToAsciiSafe(qualifierValueNode.value.rawHex);
          }

          return {
            policyQualifierId: { oid: qualifierId, label: qualifierLabel },
            qualifier: qualifierText
          };
        }).filter(Boolean);
      }
    }

    result.policies.push(policyInfo);
  }

  return result;
}

function hexToAsciiSafe(hex: string): string {
  try {
    if (!hex || typeof hex !== 'string' || hex.length % 2 !== 0) {
      return '';
    }

    let ascii = '';
    for (let i = 0; i < hex.length; i += 2) {
      const byte = parseInt(hex.substr(i, 2), 16);
      if (isNaN(byte)) {
        return '';
      }
      ascii += String.fromCharCode(byte);
    }
    return ascii;
  } catch {
    return '';
  }
}

interface AuthorityKeyIdentifier {
  keyIdentifier?: string;
  authorityCertIssuer?: string;
  authorityCertSerialNumber?: string;
}

function parseAuthorityKeyIdentifier(node: ASN1StructuredNode): AuthorityKeyIdentifier {
  const result: AuthorityKeyIdentifier = {};

  if (!node) return result;

  const rawHex = getRawHex(node);
  if (!rawHex) return result;

  const buffer = hexToArrayBuffer(rawHex);

  const parsed = parseASN1(buffer, { parseAll: true });
  if (!parsed.result || !Array.isArray(parsed.result)) {
    return result;
  }

  const topSeq = parsed.result.find(n => n.tag.type === "SEQUENCE");
  if (!topSeq || !Array.isArray(topSeq.value)) return result;

  const fields = topSeq.value as ASN1StructuredNode[];

  for (const field of fields) {
    if (field.tag.class === "CONTEXT-SPECIFIC") {
      if (field.tag.number === 0) {
        if (!Array.isArray(field.value) && field.value?.rawHex) {
          result.keyIdentifier = field.value.rawHex.toUpperCase();
        }
      } else if (field.tag.number === 1) {
        // authorityCertIssuer (GeneralNames)
        //result.authorityCertIssuer = getDecodedOrForceString(field) ?? '';
        const issuerDecoded = getDecodedOrForceString(field);
        result.authorityCertIssuer = (typeof issuerDecoded === 'string') ? issuerDecoded : '';
      } else if (field.tag.number === 2) {
        // authorityCertSerialNumber
        if (!Array.isArray(field.value) && field.value?.rawHex) {
          result.authorityCertSerialNumber = field.value.rawHex.toUpperCase();
        }
      }
    }
  }

  return result;
}

interface ExtendedKeyUsage {
  usages: { oid: string; label: string }[];
}

function parseExtendedKeyUsage(node: ASN1StructuredNode): ExtendedKeyUsage {
  const result: ExtendedKeyUsage = { usages: [] };

  if (!node) return result;

  const rawHex = getRawHex(node);
  if (!rawHex) return result;

  const buffer = hexToArrayBuffer(rawHex);

  const parsed = parseASN1(buffer, { parseAll: true });
  if (!parsed.result || !Array.isArray(parsed.result)) {
    return result;
  }

  const topSeq = parsed.result.find(n => n.tag.type === "SEQUENCE");
  if (!topSeq || !Array.isArray(topSeq.value)) return result;

  const usages = topSeq.value as ASN1StructuredNode[];

  for (const usageNode of usages) {
    const oid = getDecoded<string>(usageNode) ?? 'Unknown';
    result.usages.push({
      oid,
      label: getOIDLabel(oid)
    });
  }

  return result;
}

// ✨ X.509 Extension Parsing - Version propre, factorisée, typée
// Utilitaire de parsing ASN.1 d'une extension (OCTET STRING encapsulé)
function parseASN1FromRawHex(node: ASN1StructuredNode): ASN1StructuredNode[] {
  const rawHex = getRawHex(node);
  if (!rawHex) return [];
  const buffer = hexToArrayBuffer(rawHex);
  const parsed = parseASN1(buffer, { parseAll: true });

  const result = parsed.result;
  if (!result) return [];

  if (Array.isArray(result)) {
    const topSeq = result.find(n => n.tag.type === "SEQUENCE");
    return Array.isArray(topSeq?.value) ? topSeq.value as ASN1StructuredNode[] : [];
  }

  if (result.tag.type === "SEQUENCE" && Array.isArray(result.value)) {
    return result.value as ASN1StructuredNode[];
  }

  return [];
}

// subjectAltName (2.5.29.17)
function parseSubjectAltName(node: ASN1StructuredNode): GeneralName[] {
  const names = parseASN1FromRawHex(node);
  return names
    .filter(n => n.tag.class === "CONTEXT-SPECIFIC")
    .map(decodeGeneralName);
}

function decodeGeneralName(name: ASN1StructuredNode): GeneralName {
  switch (name.tag.number) {
    case 1: return { type: "email", value: decodeContextString(name) };
    case 2: return { type: "DNS", value: decodeContextString(name) };
    case 6: return { type: "URI", value: decodeContextString(name) };
    case 7: return { type: "IP", value: decodeIPAddress(name) };
    case 4: return { type: "directoryName", value: parseDirectoryName(name) };
    case 8: return { type: "registeredID", value: parseRegisteredID(name) };
    case 0: return { type: "otherName", value: parseOtherName(name) };
    default: return { type: `Unknown(${name.tag.number})`, value: decodeContextString(name) };
  }
}

function decodeContextString(node: ASN1StructuredNode): string {
  return (!Array.isArray(node.value) && node.value?.rawHex) ? hexToAsciiSafe(node.value.rawHex) : '';
}

function decodeIPAddress(node: ASN1StructuredNode): string {
  if (!Array.isArray(node.value) && node.value?.rawHex) {
    const hex = node.value.rawHex;
    if (hex.length === 8) return [...Array(4)].map((_, i) => parseInt(hex.substr(i * 2, 2), 16)).join('.');
    if (hex.length === 32) return [...Array(8)].map((_, i) => hex.substr(i * 4, 4)).join(':');
  }
  return '';
}

function parseDirectoryName(node: ASN1StructuredNode): string {
  const buffer = hexToArrayBuffer(node.fullHex ?? '');
  const parsed = parseASN1(buffer, { parseAll: true });
  const rdns = Array.isArray(parsed.result) ? parsed.result : (parsed.result?.value ?? []);
  return Array.isArray(rdns)
    ? rdns.map(rdn => {
        const attr = rdn.value?.[0];
        const [typeNode, valueNode] = Array.isArray(attr?.value) ? attr.value : [];
        return `${getDecoded(typeNode) ?? 'Unknown'}=${getDecoded(valueNode) ?? 'Unknown'}`;
      }).join(', ')
    : '';
}

function parseRegisteredID(node: ASN1StructuredNode): string {
  const parsed = parseASN1(hexToArrayBuffer(node.fullHex ?? ''), { parseAll: true });
  return getDecoded(parsed.result) ?? '';
}

function parseOtherName(node: ASN1StructuredNode): string {
  const parsed = parseASN1(hexToArrayBuffer(node.fullHex ?? ''), { parseAll: true });
  return JSON.stringify(parsed.result, null, 2);
}

// authorityInfoAccess (1.3.6.1.5.5.7.1.1)
interface AccessDescription {
  method: { oid: string; label: string };
  location: string;
}

interface AuthorityInfoAccess {
  accessDescriptions: AccessDescription[];
}

function parseAuthorityInfoAccess(node: ASN1StructuredNode): AuthorityInfoAccess {
  const entries = parseASN1FromRawHex(node);
  const accessDescriptions: AccessDescription[] = entries.map(desc => {
    const [methodNode, locationNode] = desc.value as ASN1StructuredNode[];
    const oid = getDecoded<string>(methodNode) ?? 'Unknown';
    const label = getOIDLabel(oid);
    const location = decodeContextString(locationNode);
    return {
      method: { oid, label },
      location
    };
  });

  return { accessDescriptions };
}

// crlDistributionPoints (2.5.29.31)
function parseCRLDistributionPoints(node: ASN1StructuredNode): { distributionPoints: string[] } {
  const entries = parseASN1FromRawHex(node);
  const distributionPoints: string[] = [];

  for (const entry of entries) {
    const dpField = (entry.value as ASN1StructuredNode[]).find(f => f.tag.class === "CONTEXT-SPECIFIC" && f.tag.number === 0);
    if (Array.isArray(dpField?.value)) {
      const inner = dpField.value[0];
      if (Array.isArray(inner?.value)) {
        inner.value.forEach(name => {
          if (name.tag.class === "CONTEXT-SPECIFIC" && name.tag.number === 6) {
            const url = decodeContextString(name);
            if (url) distributionPoints.push(url);
          }
        });
      }
    }
  }

  return { distributionPoints };
}


// SIMPLE
interface SimplifiedX509Certificate {
  version: number;
  serialNumber: string;
  signatureAlgorithm: { oid: string; label: string };
  issuer: {
    formatted: string;
    fields: { oid: string; label: string; value: string }[];
  };
  validity: {
    notBefore: string | Date;
    notAfter: string | Date;
  };
  subject: {
    formatted: string;
    fields: { oid: string; label: string; value: string }[];
  };
  subjectPublicKeyInfo: {
    algorithm: { oid: string; label: string };
    publicKey: string;
  };
  extensions?: {
    oid: string;
    label: string;
    critical: boolean;
    value: any;
  }[];
  signatureAlgorithmCert: { oid: string; label: string };
  signatureValue: string;
}

function simplifyX509Certificate(cert: X509Certificate): SimplifiedX509Certificate {
  return {
    version: cert.version.value,
    serialNumber: cert.serialNumber.value,
    signatureAlgorithm: cert.signatureAlgorithm.value,
    issuer: {
      formatted: cert.issuer.formatted.value,
      fields: cert.issuer.fields.value
    },
    validity: {
      notBefore: cert.validity.notBefore.value,
      notAfter: cert.validity.notAfter.value
    },
    subject: {
      formatted: cert.subject.formatted.value,
      fields: cert.subject.fields.value
    },
    subjectPublicKeyInfo: {
      algorithm: cert.subjectPublicKeyInfo.algorithm.value,
      publicKey: cert.subjectPublicKeyInfo.publicKey.value
    },
    extensions: cert.extensions?.map(ext => ({
      oid: ext.extnID.value.oid,
      label: ext.extnID.value.label,
      critical: ext.critical.value,
      value: ext.value.value
    })),
    signatureAlgorithmCert: cert.signatureAlgorithmCert.value,
    signatureValue: cert.signatureValue.value
  };
}

function printSimplifiedX509(cert: SimplifiedX509Certificate, indent: number = 0): void {
  const pad = (n: number) => ' '.repeat(n);
  
  const printField = (key: string, value: any, depth: number) => {
    const spacing = pad(depth * 2);
  
    const formatValue = (v: any): string => {
      if (v instanceof Date) return v.toISOString();
      if (typeof v === 'string') return `"${v}"`;
      if (typeof v === 'number' || typeof v === 'boolean') return String(v);
      return String(v);
    };
  
    if (Array.isArray(value)) {
      console.log(`${spacing}${key}:`);
      const isSimpleArray = value.every(item => typeof item !== 'object' || item === null);
      value.forEach((item, idx) => {
        if (typeof item === 'object' && item !== null) {
          console.log(`${spacing}  [${idx}]`);
          for (const [subKey, subVal] of Object.entries(item)) {
            printField(subKey, subVal, depth + 2);
          }
        } else {
          console.log(`${spacing}  - ${formatValue(item)}`);
        }
      });
    } else if (typeof value === 'object' && value !== null && !(value instanceof Date)) {
      const entries = Object.entries(value);
      const isFlat = entries.every(([_, v]) => typeof v !== 'object' || v instanceof Date);
  
      if (isFlat && entries.length > 0) {
        const flatContent = entries.map(([k, v]) => `${k}: ${formatValue(v)}`).join(', ');
        console.log(`${spacing}${key}: { ${flatContent} }`);
      } else {
        console.log(`${spacing}${key}:`);
        for (const [subKey, subVal] of entries) {
          printField(subKey, subVal, depth + 1);
        }
      }
    } else {
      console.log(`${spacing}${key}: ${formatValue(value)}`);
    }
  };

  for (const [key, value] of Object.entries(cert)) {
    printField(key, value, indent);
  }
}

function formatSimplifiedX509(
  cert: SimplifiedX509Certificate,
  options: { indent?: number; compact?: boolean } = {}
): string {
  const { indent = 0, compact = true } = options;
  const lines: string[] = [];
  const pad = (n: number) => ' '.repeat(n);

  const formatDate = (d: Date): string => {
    const yyyy = d.getUTCFullYear();
    const MM = String(d.getUTCMonth() + 1).padStart(2, '0');
    const dd = String(d.getUTCDate()).padStart(2, '0');
    const hh = String(d.getUTCHours()).padStart(2, '0');
    const mm = String(d.getUTCMinutes()).padStart(2, '0');
    const ss = String(d.getUTCSeconds()).padStart(2, '0');
    return `${yyyy}-${MM}-${dd} ${hh}:${mm}:${ss} UTC`;
  };

  const printField = (key: string, value: any, depth: number) => {
    const spacing = pad(depth * 2);

    const formatValue = (v: any): string => {
      if (v instanceof Date) return `"${formatDate(v)}"`;
      if (typeof v === 'string') return `"${v}"`;
      if (typeof v === 'number' || typeof v === 'boolean') return String(v);
      return String(v);
    };

    if (Array.isArray(value)) {
      lines.push(`${spacing}${key}:`);
      value.forEach((item, idx) => {
        if (typeof item === 'object' && item !== null) {
          lines.push(`${spacing}  [${idx}]`);
          for (const [subKey, subVal] of Object.entries(item)) {
            printField(subKey, subVal, depth + 2);
          }
        } else {
          lines.push(`${spacing}  - ${formatValue(item)}`);
        }
      });
    } else if (typeof value === 'object' && value !== null && !(value instanceof Date)) {
      const entries = Object.entries(value);
      const isFlat = entries.every(([_, v]) => typeof v !== 'object' || v instanceof Date);

      if (isFlat && entries.length > 0) {
        if (compact) {
          const flatContent = entries.map(([k, v]) => `${k}: ${formatValue(v)}`).join(', ');
          lines.push(`${spacing}${key}: { ${flatContent} }`);
        } else {
          lines.push(`${spacing}${key}:`);
          entries.forEach(([k, v]) => {
            lines.push(`${spacing}  ${k}: ${formatValue(v)}`);
          });
        }
      } else {
        lines.push(`${spacing}${key}:`);
        for (const [subKey, subVal] of entries) {
          printField(subKey, subVal, depth + 1);
        }
      }
    } else {
      lines.push(`${spacing}${key}: ${formatValue(value)}`);
    }
  };

  for (const [key, value] of Object.entries(cert)) {
    printField(key, value, indent);
  }

  return lines.join('\n');
}


/**
 * Charge un certificat X.509 à partir d'un buffer (PEM ou DER).
 * @param input - Buffer contenant un certificat en PEM ou en DER.
 * @returns X509Certificate
 * @throws Error si l'entrée n'est pas valide ou pas un certificat.
 */
//function loadX509FromBufferSync(input: Buffer | Uint8Array): X509Certificate {
function loadX509FromBufferSync(input: Uint8Array) {
  if (!input || input.length === 0) {
    throw new Error('Input buffer is empty');
  }

  let derData: Uint8Array;

  const pemString = bufferToUtf8(input);

  if (pemString.includes('-----BEGIN CERTIFICATE-----')) {
    derData = decodePEMtoDER(pemString);
  } else {
    //derData = input instanceof Buffer ? new Uint8Array(input) : input;
    if (!(input instanceof Uint8Array)) {
      throw new Error('Input must be a Uint8Array');
    }
    derData = input;
    
  }

  const parsed = parseASN1(derData.buffer.slice(derData.byteOffset, derData.byteOffset + derData.byteLength), { parseAll: true });


  if (!parsed.result) {
    throw new Error('Failed to parse ASN.1 structure: result is undefined');
  }

  let asn1Root: ASN1StructuredNode;

  if (Array.isArray(parsed.result)) {
    if (parsed.result.length === 0) {
      throw new Error('Parsed ASN.1 array is empty');
    }
    asn1Root = parsed.result[0];
  } else {
    asn1Root = parsed.result;
  }

  if (!asn1Root || !asn1Root.tag || !asn1Root.value) {
    throw new Error('Invalid ASN.1 root node');
  }

  if (asn1Root.tag.type !== 'SEQUENCE') {
    throw new Error(`Expected ASN.1 SEQUENCE at root, got: ${asn1Root.tag.type}`);
  }

  return parseX509Certificate(asn1Root);
}

/**
 * Convertit un buffer en texte UTF-8.
 */
/*
function bufferToUtf8(buffer: Buffer | Uint8Array): string {
  return Buffer.isBuffer(buffer)
    ? buffer.toString('utf-8')
    : new TextDecoder('utf-8').decode(buffer);
}
*/
function bufferToUtf8(buffer: Uint8Array): string {
  return new TextDecoder('utf-8').decode(buffer);
}

/**
 * Décapsule un PEM en DER.
 */
/*
function decodePEMtoDER(pem: string): Uint8Array {
  const match = pem.match(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/);
  if (!match || !match[1]) {
    throw new Error('Invalid PEM format');
  }
  const base64 = match[1].replace(/\s+/g, '');
  const binary = Buffer.from(base64, 'base64');
  return new Uint8Array(binary);
}
*/
function decodePEMtoDER(pem: string): Uint8Array {
  const match = pem.match(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/);
  if (!match || !match[1]) {
    throw new Error('Invalid PEM format');
  }
  const base64 = match[1].replace(/\s+/g, '');
  
  // Decode base64 manually
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}



// Plusieurs certificats
/**
 * Charge tous les certificats X.509 trouvés dans un buffer (PEM multiples ou DER unique).
 * @param input - Buffer contenant un ou plusieurs certificats.
 * @returns Liste de X509Certificate
 * @throws Error si aucun certificat trouvé ou si parsing échoue.
 */
//function loadX509AllFromBufferSync(input: Buffer | Uint8Array): X509Certificate[] {
function loadX509AllFromBufferSync(input: Uint8Array): X509Certificate[] {
  if (!input || input.length === 0) {
    throw new Error('Input buffer is empty');
  }

  const pemString = bufferToUtf8(input);

  const certificates: X509Certificate[] = [];

  if (pemString.includes('-----BEGIN CERTIFICATE-----')) {
    const matches = pemString.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
    if (!matches || matches.length === 0) {
      throw new Error('No PEM certificates found in input');
    }

    for (const pem of matches) {
      const derData = decodePEMtoDER(pem);
      const parsed = parseASN1(derData.buffer.slice(derData.byteOffset, derData.byteOffset + derData.byteLength), { parseAll: true });

      if (!parsed.result) {
        throw new Error('Failed to parse ASN.1 structure for one of the PEM certificates');
      }

      const asn1Root = Array.isArray(parsed.result) ? parsed.result[0] : parsed.result;

      if (!asn1Root || asn1Root.tag.type !== 'SEQUENCE') {
        throw new Error('Invalid ASN.1 root node in one of the certificates');
      }

      certificates.push(parseX509Certificate(asn1Root));
    }
  } else {
    // Unique DER
    //const derData = input instanceof Buffer ? new Uint8Array(input) : input;
    const derData = input;
    const parsed = parseASN1(derData.buffer.slice(derData.byteOffset, derData.byteOffset + derData.byteLength), { parseAll: true });

    if (!parsed.result) {
      throw new Error('Failed to parse ASN.1 structure');
    }

    const asn1Root = Array.isArray(parsed.result) ? parsed.result[0] : parsed.result;

    if (!asn1Root || asn1Root.tag.type !== 'SEQUENCE') {
      throw new Error('Invalid ASN.1 root node');
    }

    certificates.push(parseX509Certificate(asn1Root));
  }

  if (certificates.length === 0) {
    throw new Error('No valid X.509 certificates found');
  }

  return certificates;
}

/**
 * Simplifie une liste de certificats X.509.
 * @param certs - Liste des certificats X.509 bruts.
 * @returns Liste simplifiée.
 */
function simplifyX509All(certs: X509Certificate[]): SimplifiedX509Certificate[] {
  return certs.map(cert => simplifyX509Certificate(cert));
}

/**
 * Affiche une liste de certificats X.509 simplifiés.
 * @param certs - Liste simplifiée.
 */
function printSimplifiedX509All(certs: SimplifiedX509Certificate[], indent: number = 0): void {
  certs.forEach((cert, index) => {
    console.log(`Certificate [${index}]`);
    printSimplifiedX509(cert, indent + 1);
    console.log('');
  });
}

function formatSimplifiedX509AllAsJSON(certs: SimplifiedX509Certificate[]): string {
  return JSON.stringify(certs, (_k, v) => (v instanceof Date ? v.toISOString() : v), 2);
}


export {
  parseX509Certificate,
  loadX509FromBufferSync,
  loadX509AllFromBufferSync,
  simplifyX509Certificate,
  simplifyX509All,
  printSimplifiedX509,
  printSimplifiedX509All,
  formatSimplifiedX509,
  formatSimplifiedX509AllAsJSON,
  SimplifiedX509Certificate
};

