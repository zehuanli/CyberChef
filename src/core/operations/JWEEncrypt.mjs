/**
 * JWE Decrypt operation
 * Decrypts JSON Web Encryption tokens using HKDF-derived keys
 *
 * @author Zehuan
 * @license MIT
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import * as jose from "jose";
import { hkdf } from "@panva/hkdf";

/**
 * JWE Encrypt operation
 */
class JWEEncrypt extends Operation {

    /**
     * JWEEncrypt constructor
     */
    constructor() {
        super();

        this.name = "JWE Encrypt";
        this.module = "Crypto";
        this.description = "Encrypts data into JSON Web Encryption (JWE) tokens using a secret key derived through HKDF (HMAC-based Key Derivation Function).<br><br>The operation uses HKDF to derive an encryption key from your secret, then creates a JWE token in compact serialization format (5 Base64URL parts separated by dots).";
        this.infoURL = "https://datatracker.ietf.org/doc/html/rfc7516";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [
            {
                name: "Secret",
                type: "string",
                value: "",
                description: "The secret used to derive the encryption key"
            },
            {
                name: "Algorithm",
                type: "option",
                value: ["dir", "A128KW", "A192KW", "A256KW", "A128GCMKW", "A192GCMKW", "A256GCMKW"],
                defaultIndex: 0,
                description: "Key management algorithm. 'dir' uses the derived key directly"
            },
            {
                name: "Encryption",
                type: "option",
                value: ["A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"],
                defaultIndex: 2,
                description: "Content encryption algorithm"
            },
            {
                name: "Key Length (bytes)",
                type: "option",
                value: ["16", "24", "32", "48", "64"],
                defaultIndex: 2,
                description: "Derived key length in bytes. Must match the algorithm requirements"
            },
            {
                name: "Encryption Info",
                type: "string",
                value: "JWE CEK",
                description: "Context/info string for HKDF. Common values: 'JWE CEK', 'WebAuthn secret', 'encryption', or custom context"
            },
            {
                name: "Digest Algorithm",
                type: "option",
                value: ["sha256", "sha384", "sha512", "sha1"],
                defaultIndex: 0,
                description: "Hash algorithm for HKDF. SHA-256 is most common"
            },
            {
                name: "Salt",
                type: "string",
                value: "",
                description: "Optional salt value (hex or UTF-8). Leave empty for no salt"
            },
            {
                name: "Salt Encoding",
                type: "option",
                value: ["UTF-8", "Hex", "Base64"],
                defaultIndex: 0,
                description: "How to interpret the salt input"
            },
            {
                name: "Payload Type",
                type: "option",
                value: ["JSON", "String"],
                defaultIndex: 0,
                description: "Whether to parse input as JSON or treat as string"
            },
            {
                name: "Include Headers",
                type: "text",
                value: "",
                description: "Additional JWE headers as JSON (e.g., {\"kid\": \"key-id\"}). Leave empty for none"
            }
        ];
    }

    /**
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    async run(input, args) {
        const [
            secret,
            algorithm,
            encryption,
            keyLength,
            encryptionInfo,
            digestAlg,
            salt,
            saltEncoding,
            payloadType,
            additionalHeaders
        ] = args;

        if (!input || !input.trim()) {
            throw new OperationError("No payload provided to encrypt");
        }

        if (!secret || !secret.trim()) {
            throw new OperationError("No secret provided");
        }

        try {
            // Parse parameters
            const BYTE_LENGTH = parseInt(keyLength, 10);
            const ENCRYPTION_INFO = encryptionInfo || "JWE CEK";
            const digest = digestAlg;

            // Process salt based on encoding
            let saltBuffer = "";
            if (salt && salt.trim()) {
                switch (saltEncoding) {
                    case "Hex":
                        saltBuffer = Buffer.from(salt.replace(/\s/g, ""), "hex");
                        break;
                    case "Base64":
                        saltBuffer = Buffer.from(salt, "base64");
                        break;
                    case "UTF-8":
                    default:
                        saltBuffer = salt;
                        break;
                }
            }

            // Derive the key using HKDF
            const derivedKey = await hkdf(
                digest,
                secret,
                saltBuffer,
                ENCRYPTION_INFO,
                BYTE_LENGTH
            );

            // Parse the payload
            let payload;
            if (payloadType === "JSON") {
                try {
                    payload = JSON.parse(input.trim());
                } catch (e) {
                    throw new OperationError("Invalid JSON payload: " + e.message);
                }
            } else {
                payload = input.trim();
            }

            // Parse and add additional headers if provided
            let headers = {};
            if (additionalHeaders && additionalHeaders.trim()) {
                try {
                    headers = JSON.parse(additionalHeaders.trim());
                } catch (e) {
                    throw new OperationError("Invalid additional headers JSON: " + e.message);
                }
            }

            // Create the JWE
            const jwe = await new jose.CompactEncrypt(
                new TextEncoder().encode(
                    typeof payload === "string" ? payload : JSON.stringify(payload)
                )
            )
                .setProtectedHeader({
                    alg: algorithm,
                    enc: encryption,
                    ...headers
                })
                .encrypt(derivedKey);

            // Return the compact serialization
            return jwe;

        } catch (err) {
            if (err instanceof OperationError) {
                throw err;
            } else if (err.message.includes("Invalid key size")) {
                throw new OperationError(`Invalid key size for algorithm ${algorithm}. Common sizes: dir/A256GCM needs 32 bytes, A128GCM needs 16 bytes.`);
            } else if (err.message.includes("unsupported")) {
                throw new OperationError(`Unsupported algorithm combination: ${algorithm} with ${encryption}`);
            } else {
                throw new OperationError(`Error encrypting JWE: ${err.message}`);
            }
        }
    }

    /**
     * Highlight JWE Encrypt in the operation search results
     * @param {string} pos
     * @param {number} pos.start
     * @param {number} pos.end
     * @param {Object[]} args
     * @returns {Object[]} pos
     */
    present(pos, args) {
        // This method is used for highlighting in CyberChef's UI
        return pos;
    }
}

export default JWEEncrypt;
