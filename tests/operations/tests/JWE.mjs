/**
 * JWE Encrypt and Decrypt operation tests
 *
 * @author Zehuan
 * @license MIT
 */
import TestRegister from "../../lib/TestRegister.mjs";

TestRegister.addTests([
    {
        name: "JWE Encrypt: JSON payload",
        input: '{"user": "alice", "role": "admin"}',
        expectedOutput: "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..Y5hiP5YW788yMtJ0.q47NDx7p3tiee0_n_ag_sVxUZs8mUhrvzS1HKiA91w.kV88OvG-ENwfgSLh6-tVLA",
        recipeConfig: [
            {
                op: "JWE Encrypt",
                args: [
                    "test-secret-key",     // Secret
                    "dir",                 // Algorithm
                    "A256GCM",             // Encryption
                    "32",                  // Key Length (bytes)
                    "JWE CEK",             // Encryption Info
                    "sha256",              // Digest Algorithm
                    "",                    // Salt
                    "UTF-8",               // Salt Encoding
                    "JSON",                // Payload Type
                    ""                     // Include Headers
                ],
            },
        ],
    },
    {
        name: "JWE Encrypt: With custom headers",
        input: '{"user": "alice", "role": "admin"}',
        expectedOutput: "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoidGVzdC1rZXkifQ..W383sa8MmuAg7k39.mkvAmcL0D4kdkoZQyKIlQ_wDxsA-mACE2i1ZZImQiA.eWpGFW9doejplHwIwDGxVg",
        recipeConfig: [
            {
                op: "JWE Encrypt",
                args: [
                    "test-secret-key",     // Secret
                    "dir",                 // Algorithm
                    "A256GCM",             // Encryption
                    "32",                  // Key Length (bytes)
                    "JWE CEK",             // Encryption Info
                    "sha256",              // Digest Algorithm
                    "",                    // Salt
                    "UTF-8",               // Salt Encoding
                    "JSON",                // Payload Type
                    '{"kid": "test-key"}'  // Include Headers
                ],
            },
        ],
    },
    {
        name: "JWE Encrypt, Decrypt: Round trip",
        input: '{"userId": 123, "permissions": ["read", "write", "delete"]}',
        expectedOutput: '{"userId": 123, "permissions": ["read", "write", "delete"]}',
        recipeConfig: [
            {
                op: "JWE Encrypt",
                args: [
                    "test-secret-key",     // Secret
                    "dir",                 // Algorithm
                    "A256GCM",             // Encryption
                    "32",                  // Key Length (bytes)
                    "JWE CEK",             // Encryption Info
                    "sha256",              // Digest Algorithm
                    "",                    // Salt
                    "UTF-8",               // Salt Encoding
                    "JSON",                // Payload Type
                    ""                     // Include Headers
                ],
            },
            {
                op: "JWE Decrypt",
                args: [
                    "test-secret-key",     // Secret
                    "32",                  // Key Length (bytes)
                    "JWE CEK",             // Encryption Info
                    "sha256",              // Digest Algorithm
                    "",                    // Salt
                    "UTF-8",               // Salt Encoding
                    "Raw Payload"          // Output Format
                ],
            },
        ],
    },
    {
        name: "JWE Decrypt: JSON",
        // This is a test token encrypted with "test-secret-key" and default settings
        input: "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..Y5hiP5YW788yMtJ0.q47NDx7p3tiee0_n_ag_sVxUZs8mUhrvzS1HKiA91w.kV88OvG-ENwfgSLh6-tVLA",
        expectedOutput: '{"user": "alice", "role": "admin"}',
        recipeConfig: [
            {
                op: "JWE Decrypt",
                args: [
                    "test-secret-key",     // Secret
                    "32",                  // Key Length (bytes)
                    "JWE CEK",             // Encryption Info
                    "sha256",              // Digest Algorithm
                    "",                    // Salt
                    "UTF-8",               // Salt Encoding
                    "Raw Payload"          // Output Format
                ],
            },
        ],
    },
    {
        name: "JWE Encrypt: Error on empty secret",
        input: '{"user": "alice", "role": "admin"}',
        expectedError: true,
        expectedOutput: "No secret provided",
        recipeConfig: [
            {
                op: "JWE Encrypt",
                args: [
                    "",                    // Secret (empty)
                    "dir",                 // Algorithm
                    "A256GCM",             // Encryption
                    "32",                  // Key Length (bytes)
                    "JWE CEK",             // Encryption Info
                    "sha256",              // Digest Algorithm
                    "",                    // Salt
                    "UTF-8",               // Salt Encoding
                    "JSON",                // Payload Type
                    ""                     // Include Headers
                ],
            },
        ],
    },
    {
        name: "JWE Decrypt: Error on invalid token format",
        input: "not.a.valid.jwe",
        expectedError: true,
        expectedOutput: "Invalid JWE token format. Expected 5 parts separated by dots.",
        recipeConfig: [
            {
                op: "JWE Decrypt",
                args: [
                    "test-secret",         // Secret
                    "32",                  // Key Length (bytes)
                    "JWE CEK",             // Encryption Info
                    "sha256",              // Digest Algorithm
                    "",                    // Salt
                    "UTF-8",               // Salt Encoding
                    "JSON"                 // Output Format
                ],
            },
        ],
    },
    {
        name: "JWE Encrypt: Error on invalid JSON payload",
        input: '{"invalid": json}',
        expectedError: true,
        expectedOutput: "Invalid JSON payload:",
        recipeConfig: [
            {
                op: "JWE Encrypt",
                args: [
                    "test-secret",         // Secret
                    "dir",                 // Algorithm
                    "A256GCM",             // Encryption
                    "32",                  // Key Length (bytes)
                    "JWE CEK",             // Encryption Info
                    "sha256",              // Digest Algorithm
                    "",                    // Salt
                    "UTF-8",               // Salt Encoding
                    "JSON",                // Payload Type (expecting valid JSON)
                    ""                     // Include Headers
                ],
            },
        ],
    },
    {
        name: "JWE Encrypt, Decrypt: With salt",
        input: '{"user": "alice", "role": "admin"}',
        expectedOutput: '{"user": "alice", "role": "admin"}',
        recipeConfig: [
            {
                op: "JWE Encrypt",
                args: [
                    "test-secret",         // Secret
                    "dir",                 // Algorithm
                    "A256GCM",             // Encryption
                    "32",                  // Key Length (bytes)
                    "JWE CEK",             // Encryption Info
                    "sha256",              // Digest Algorithm
                    "user123",             // Salt
                    "UTF-8",               // Salt Encoding
                    "JSON",                // Payload Type
                    ""                     // Include Headers
                ],
            },
            {
                op: "JWE Decrypt",
                args: [
                    "test-secret",         // Secret
                    "32",                  // Key Length (bytes)
                    "JWE CEK",             // Encryption Info
                    "sha256",              // Digest Algorithm
                    "user123",             // Salt (must match)
                    "UTF-8",               // Salt Encoding
                    "Raw Payload"          // Output Format
                ],
            },
        ],
    },
]);
