type ASN1TagClass = "UNIVERSAL" | "APPLICATION" | "CONTEXT-SPECIFIC" | "PRIVATE";

export interface ASN1StructuredNode {
    tag: {
        number: number;
        hex: string;
        class: ASN1TagClass;
        constructed: boolean;
        type: string;
    };
    length: {
        value: number;
        encodedHex: string;
    };
    value: ASN1StructuredNode[] | {
        rawHex: string;
        base64?: string;
        decoded?: string | number;
    };
    offset: number;
    fullHex: string;
}

class ASN1Parser {
    private view: DataView;
	private options: { parseAll: boolean; simplify: boolean };
    private offset: number = 0;
	private errors: string[] = [];

	
    constructor(
        private buffer: ArrayBuffer,
        options?: { parseAll?: boolean; simplify?: boolean }
    ) {
        this.view = new DataView(buffer);

        this.options = {
            parseAll: true,
            simplify: false,
            ...options
        };
    }
	
	public parse(): { result: ASN1StructuredNode | ASN1StructuredNode[] | any; errors: string[] } {
		const nodes: ASN1StructuredNode[] = [];

		while (this.offset < this.buffer.byteLength) {
			try {
				const node = this.parseElement();
				nodes.push(node);
			} catch (e) {
				this.errors.push(`Error parsing ASN.1 at offset ${this.offset}: ${e}`);
				break; // Ou continue ici si tu veux parser ce qu’il reste
			}

			if (!this.options?.parseAll) {
				break;
			}
		}

		const result = this.options?.simplify
			? (this.options.parseAll ? nodes.map(node => this.simplifyNode(node)) : this.simplifyNode(nodes[0]))
			: (this.options.parseAll ? nodes : nodes[0]);

		return { result, errors: this.errors };
	}

	
	private simplifyNode(node: ASN1StructuredNode): any {
		const simple: any = {};

		simple.tag = node.tag.type;
		simple.class = node.tag.class;
		simple.offset = node.offset;
		if (Array.isArray(node.value)) {
			simple.value = node.value.map(child => this.simplifyNode(child));
		} else {
			simple.value = node.value.decoded ?? node.value.base64 ?? node.value.rawHex;
		}
		return simple;
	}



	private parseElement(): ASN1StructuredNode {
		
		const startOffset = this.offset;
		const tagByte = this.readByte();
		const tagHex = tagByte.toString(16).padStart(2, '0');
		const tagClass = this.getTagClass(tagByte);
		const constructed = (tagByte & 0x20) !== 0;
		
		let tagNumber = tagByte & 0x1F;
		if (tagNumber === 0x1F) {
			tagNumber = 0;
			let byte;
			do {
				byte = this.readByte();
				tagNumber = (tagNumber << 7) | (byte & 0x7F);
			} while (byte & 0x80);
		}

		const lengthStart = this.offset;
		const lengthValue = this.readLength();
		if (this.offset + lengthValue > this.buffer.byteLength) {
			throw new Error(`Declared length extends beyond buffer at offset ${startOffset}`);
		}
		const lengthEncodedHex = this.bytesToHex(new Uint8Array(this.buffer.slice(lengthStart, this.offset)));

		const typeName = this.tagToType(tagNumber);

		if (constructed) {
			const endOffset = this.offset + lengthValue;
			const value: ASN1StructuredNode[] = [];

			while (this.offset < endOffset) {
				value.push(this.parseElement());
			}

			const fullHex = this.bytesToHex(new Uint8Array(this.buffer.slice(startOffset, endOffset)));

			return {
				tag: {
					number: tagNumber,
					hex: tagHex,
					class: tagClass,
					constructed: true,
					type: typeName
				},
				length: {
					value: lengthValue,
					encodedHex: lengthEncodedHex
				},
				value,
				offset: startOffset,
				fullHex
			};
		} else {
			const valueBytes = this.readBytes(lengthValue);
			const fullHex = this.bytesToHex(new Uint8Array(this.buffer.slice(startOffset, this.offset)));
			const valueHex = this.bytesToHex(valueBytes);

			const valueObject: any = {
				rawHex: valueHex
			};

			// Décodages spéciaux
			if (tagNumber === 0x01) { // BOOLEAN
				valueObject.decoded = this.decodeBoolean(valueBytes);
			}
			if (tagNumber === 0x02) { // INTEGER
				valueObject.decoded = this.decodeInteger(valueBytes);
			}
			if (tagNumber === 0x03) { // BIT STRING
				valueObject.decoded = this.decodeBitString(valueBytes);
			}
			if (tagNumber === 0x04) { // OCTET STRING
				valueObject.base64 = this.bytesToBase64(valueBytes);
			}
			if (tagNumber === 0x06) { // OBJECT IDENTIFIER
				valueObject.decoded = this.decodeOID(valueBytes);
			}
			if (tagNumber === 0x09) { // REAL
				valueObject.decoded = this.decodeReal(valueBytes);
			}
			if (tagNumber === 0x0A) { // ENUMERATED
				valueObject.decoded = this.decodeInteger(valueBytes);
			}
			if (tagNumber === 0x0C || tagNumber === 0x13) { // UTF8String ou PrintableString
				valueObject.decoded = this.decodeString(valueBytes);
			}
			if (tagNumber === 0x17 || tagNumber === 0x18) { // UTCTime ou GeneralizedTime
				valueObject.decoded = this.decodeDate(valueBytes, tagNumber);
			}


			return {
				tag: {
					number: tagNumber,
					hex: tagHex,
					class: tagClass,
					constructed: false,
					type: typeName
				},
				length: {
					value: lengthValue,
					encodedHex: lengthEncodedHex
				},
				value: valueObject,
				offset: startOffset,
				fullHex
			};
		}
	}

    private readByte(): number {
        const byte = this.view.getUint8(this.offset);
        this.offset += 1;
        return byte;
    }

    private readBytes(length: number): Uint8Array {
        const bytes = new Uint8Array(this.buffer, this.offset, length);
        this.offset += length;
        return bytes;
    }
	
	private readLength(): number {
		const firstByte = this.readByte();
		if ((firstByte & 0x80) === 0) {
			return firstByte;
		} else {
			const numBytes = firstByte & 0x7F;
			if (numBytes === 0 || numBytes > 4) {
				throw new Error(`Invalid length encoding at offset ${this.offset - 1}`);
			}
			if (this.offset + numBytes > this.buffer.byteLength) {
				throw new Error(`Length extends beyond buffer at offset ${this.offset}`);
			}
			let length = 0;
			for (let i = 0; i < numBytes; i++) {
				length = (length << 8) | this.readByte();
			}
			return length;
		}
	}


    private bytesToHex(bytes: Uint8Array): string {
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    private decodeString(bytes: Uint8Array): string {
        return new TextDecoder("utf-8").decode(bytes);
    }

    private decodeOID(bytes: Uint8Array): string {
        if (bytes.length === 0) return "";

        const firstByte = bytes[0];
        const first = Math.floor(firstByte / 40);
        const second = firstByte % 40;

        const parts = [first, second];
        let value = 0;

        for (let i = 1; i < bytes.length; i++) {
            value = (value << 7) | (bytes[i] & 0x7F);
            if ((bytes[i] & 0x80) === 0) {
                parts.push(value);
                value = 0;
            }
        }

        return parts.join('.');
    }
	
	
	private decodeInteger(bytes: Uint8Array): number {
		let result = 0;
		for (let i = 0; i < bytes.length; i++) {
			result = (result << 8) | bytes[i];
		}
		if (bytes.length > 0 && (bytes[0] & 0x80)) {
			result -= 1 << (bytes.length * 8);
		}
		return result;
	}

	private decodeBitString(bytes: Uint8Array): { unusedBits: number; dataHex: string } {
		if (bytes.length === 0) return { unusedBits: 0, dataHex: '' };
		const unusedBits = bytes[0];
		const dataBytes = bytes.slice(1);
		const dataHex = this.bytesToHex(dataBytes);
		return {
			unusedBits,
			dataHex
		};
	}

	private decodeDate(bytes: Uint8Array, tagNumber: number): Date | string {
		const str = this.decodeString(bytes);
		try {
			if (tagNumber === 0x17) { // UTCTime
				// Format YYMMDDhhmmssZ ou YYMMDDhhmmZ
				const match = str.match(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/);
				if (match) {
					const year = parseInt(match[1], 10);
					const fullYear = year < 50 ? 2000 + year : 1900 + year; // ASN.1 convention
					const month = parseInt(match[2], 10) - 1;
					const day = parseInt(match[3], 10);
					const hour = parseInt(match[4], 10);
					const minute = parseInt(match[5], 10);
					const second = match[6] ? parseInt(match[6], 10) : 0;
					return new Date(Date.UTC(fullYear, month, day, hour, minute, second));
				}
			} else if (tagNumber === 0x18) { // GeneralizedTime
				// Format YYYYMMDDhhmmssZ
				const match = str.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/);
				if (match) {
					const year = parseInt(match[1], 10);
					const month = parseInt(match[2], 10) - 1;
					const day = parseInt(match[3], 10);
					const hour = parseInt(match[4], 10);
					const minute = parseInt(match[5], 10);
					const second = match[6] ? parseInt(match[6], 10) : 0;
					return new Date(Date.UTC(year, month, day, hour, minute, second));
				}
			}
		} catch (e) {
			return str; // fallback si parsing échoue
		}
		return str; // fallback
	}

	private decodeBoolean(bytes: Uint8Array): boolean {
		if (bytes.length !== 1) {
			return false;
		}
		return bytes[0] !== 0x00;
	}

	private decodeReal(bytes: Uint8Array): number | string {
		if (bytes.length === 0) {
			return 0;
		}

		const firstByte = bytes[0];

		// Special values
		if (firstByte === 0x40) return Infinity;
		if (firstByte === 0x41) return -Infinity;
		if (firstByte === 0x42) return NaN;
		if (firstByte === 0x43) return -0;

		// Binary encoding
		if ((firstByte & 0x80) === 0x80) {
			const baseIndicator = (firstByte >> 4) & 0x03; // bits 6-5
			const scaleFactor = (firstByte >> 2) & 0x03;   // bits 4-3
			const exponentLength = (firstByte & 0x03) + 1; // bits 1-0 + 1

			let exponent = 0;
			for (let i = 0; i < exponentLength; i++) {
				exponent = (exponent << 8) | bytes[1 + i];
			}

			// Exponent sign bit
			if ((bytes[1] & 0x80) !== 0) {
				exponent -= (1 << (8 * exponentLength));
			}

			const mantissaBytes = bytes.slice(1 + exponentLength);
			let mantissa = 0;
			for (let i = 0; i < mantissaBytes.length; i++) {
				mantissa = (mantissa << 8) | mantissaBytes[i];
			}

			if (mantissaBytes.length > 0 && (mantissaBytes[0] & 0x80)) {
				mantissa -= (1 << (8 * mantissaBytes.length));
			}

			// Apply scale factor (multiplying/dividing mantissa)
			mantissa = mantissa * Math.pow(2, scaleFactor * 3);

			let base = 2;
			if (baseIndicator === 1) base = 8;
			if (baseIndicator === 2) base = 16;

			const value = mantissa * Math.pow(base, exponent);
			return value;
		} else {
			// Otherwise, assume it's an ASCII-encoded decimal string
			return parseFloat(this.decodeString(bytes));
		}
	}


	private bytesToBase64(bytes: Uint8Array): string {
		// Rapide et sans concat de caractères un par un
		return btoa(String.fromCharCode(...bytes));
	}


    private getTagClass(tagByte: number): ASN1TagClass {
        const cls = (tagByte & 0xC0) >> 6;
        switch (cls) {
            case 0: return "UNIVERSAL";
            case 1: return "APPLICATION";
            case 2: return "CONTEXT-SPECIFIC";
            case 3: return "PRIVATE";
            default: return "UNIVERSAL";
        }
    }

    private tagToType(tag: number): string {
        switch (tag) {
            case 0x01: return "BOOLEAN";
            case 0x02: return "INTEGER";
            case 0x03: return "BIT STRING";
            case 0x04: return "OCTET STRING";
            case 0x05: return "NULL";
            case 0x06: return "OBJECT IDENTIFIER";
			case 0x07: return "ObjectDescriptor";
			case 0x08: return "EXTERNAL";
			case 0x09: return "REAL";
			case 0x0A: return "ENUMERATED";
			case 0x0B: return "EMBEDDED PDV";
            case 0x0C: return "UTF8String";
			case 0x0D: return "RELATIVE-OID";
			case 0x10: return "SEQUENCE";
			case 0x11: return "SET";
			case 0x12: return "NumericString";
            case 0x13: return "PrintableString";
			case 0x14: return "TeletexString";
			case 0x15: return "VideotexString";
			case 0x16: return "IA5String";
            case 0x17: return "UTCTime";
            case 0x18: return "GeneralizedTime";
            case 0x19: return "GraphicString";
			case 0x1A: return "VisibleString";
			case 0x1B: return "GeneralString";
			case 0x1C: return "UniversalString";
			case 0x1D: return "CHARACTER STRING";
			case 0x1E: return "BMPString";
            default:
                return `Unknown (0x${tag.toString(16)})`;
        }
    }
}

// Exemple d'utilisation :

export function parseASN1(
    buffer: ArrayBuffer, 
    options: { parseAll?: boolean; simplify?: boolean } = {}
): { result: ASN1StructuredNode | ASN1StructuredNode[] | any; errors: string[] } {
    const parser = new ASN1Parser(buffer, options);
    return parser.parse();
}
