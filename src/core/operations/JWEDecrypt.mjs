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
 * JWE Decrypt operation
 */
class JWEDecrypt extends Operation {

    /**
     * JWEDecrypt constructor
     */
    constructor() {
        super();

        this.name = "JWE Decrypt";
        this.module = "Crypto";
        this.description = "Decrypts JSON Web Encryption (JWE) tokens using a secret key derived through HKDF (HMAC-based Key Derivation Function).<br><br>The operation uses SHA-256 for HKDF with 'JWE CEK' as the encryption info parameter.";
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
                name: "Key Length (bytes)",
                type: "option",
                value: ["16", "24", "32", "48", "64"],
                defaultIndex: 2,
                description: "Derived key length in bytes. 16=AES-128, 24=AES-192, 32=AES-256, 48=AES-384, 64=AES-512"
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
                name: "Output Format",
                type: "option",
                value: ["JSON", "Pretty JSON", "Raw Payload"],
                defaultIndex: 1,
                description: "How to format the decrypted output"
            }
        ];
    }

    /**
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    async run(input, args) {
        const [secret, keyLength, encryptionInfo, digestAlg, salt, saltEncoding, outputFormat] = args;

        if (!input || !input.trim()) {
            throw new OperationError("No JWE token provided");
        }

        if (!secret || !secret.trim()) {
            throw new OperationError("No secret provided");
        }

        const jweToken = input.trim();

        // Validate JWE format (should have 5 parts separated by dots)
        const parts = jweToken.split(".");
        if (parts.length !== 5) {
            throw new OperationError("Invalid JWE token format. Expected 5 parts separated by dots.");
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
                        // Convert hex string to buffer
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

            // Decrypt the JWE
            const result = await jose.jwtDecrypt(jweToken, derivedKey);

            // Format output based on selected option
            switch (outputFormat) {
                case "JSON":
                    return JSON.stringify(result.payload);
                case "Pretty JSON":
                    return JSON.stringify(result.payload, null, 2);
                case "Raw Payload":
                    // If payload is a string, return it directly
                    if (typeof result.payload === "string") {
                        return result.payload;
                    }
                    // Otherwise stringify it
                    return JSON.stringify(result.payload);
                default:
                    return JSON.stringify(result.payload, null, 2);
            }

        } catch (err) {
            if (err.message.includes("decryption operation failed")) {
                throw new OperationError("Failed to decrypt JWE. Please check that the secret is correct and the token is valid.");
            } else if (err.message.includes("Unsupported")) {
                throw new OperationError(`Unsupported JWE algorithm or encryption method: ${err.message}`);
            } else {
                throw new OperationError(`Error decrypting JWE: ${err.message}`);
            }
        }
    }

    /**
     * Highlight JWE Decrypt in the operation search results
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

export default JWEDecrypt;
