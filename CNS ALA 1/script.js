/*
=========================================================
SECURE MESSAGING WEB APPLICATION
AES + RSA HYBRID ENCRYPTION
=========================================================

AES-GCM:
    Encrypts the actual message.

RSA-OAEP:
    Encrypts/wraps the AES key.

Web Crypto API:
    Browser built-in cryptographic API.

Encryption:
    Message
       ↓
    AES-GCM
       ↓
    Encrypted Message

    AES Key
       ↓
    RSA-OAEP using Public Key
       ↓
    Encrypted AES Key

Decryption:
    Encrypted AES Key
       ↓
    RSA-OAEP using Private Key
       ↓
    AES Key
       ↓
    AES-GCM
       ↓
    Original Message
=========================================================
*/


// =====================================================
// DOM ELEMENTS
// =====================================================

const messageInput =
    document.getElementById("message");

const encryptBtn =
    document.getElementById("encryptBtn");

const decryptBtn =
    document.getElementById("decryptBtn");

const resetBtn =
    document.getElementById("resetBtn");

const aesKeyOutput =
    document.getElementById("aesKey");

const encryptedKeyOutput =
    document.getElementById("encryptedKey");

const encryptedMessageOutput =
    document.getElementById("encryptedMessage");

const decryptedMessageOutput =
    document.getElementById("decryptedMessage");

const statusBadge =
    document.getElementById("statusBadge");


// =====================================================
// GLOBAL VARIABLES
// =====================================================

// RSA public/private key pair
let rsaKeyPair = null;

// AES key generated for the current message
let aesKey = null;

// AES IV
let aesIv = null;

// Encrypted AES key
let encryptedAesKey = null;

// Encrypted message
let encryptedMessage = null;


// =====================================================
// UTILITY FUNCTIONS
// =====================================================


/*
Convert ArrayBuffer / Uint8Array to Base64
*/
function arrayBufferToBase64(buffer) {

    const bytes = new Uint8Array(buffer);

    let binary = "";

    const chunkSize = 0x8000;

    for (
        let i = 0;
        i < bytes.length;
        i += chunkSize
    ) {

        const chunk =
            bytes.subarray(
                i,
                Math.min(i + chunkSize, bytes.length)
            );

        binary += String.fromCharCode(...chunk);
    }

    return btoa(binary);
}


/*
Convert Base64 to Uint8Array
*/
function base64ToUint8Array(base64) {

    const binary =
        atob(base64);

    const bytes =
        new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {

        bytes[i] =
            binary.charCodeAt(i);
    }

    return bytes;
}


/*
Update status badge
*/
function updateStatus(text, type) {

    statusBadge.textContent = text;

    statusBadge.className =
        `status ${type}`;
}


/*
Clear output
*/
function clearOutputs() {

    aesKeyOutput.value = "";

    encryptedKeyOutput.value = "";

    encryptedMessageOutput.value = "";

    decryptedMessageOutput.textContent =
        "Decrypted message will appear here...";
}


// =====================================================
// GENERATE RSA KEY PAIR
// =====================================================

async function generateRSAKeys() {

    /*
    RSA-OAEP key pair

    Public Key:
        Used by sender to encrypt the AES key.

    Private Key:
        Used by recipient to decrypt the AES key.
    */

    rsaKeyPair =
        await crypto.subtle.generateKey(

            {
                name: "RSA-OAEP",

                modulusLength: 4096,

                publicExponent:
                    new Uint8Array([1, 0, 1]),

                hash: "SHA-256"
            },

            true,

            [
                "encrypt",
                "decrypt"
            ]
        );

    console.log(
        "RSA public/private key pair generated."
    );
}


// =====================================================
// AES ENCRYPTION
// =====================================================

async function encryptMessage(message) {

    /*
    Generate a random 256-bit AES-GCM key.
    */

    aesKey =
        await crypto.subtle.generateKey(

            {
                name: "AES-GCM",

                length: 256
            },

            true,

            [
                "encrypt",
                "decrypt"
            ]
        );


    /*
    Generate a random 12-byte IV.

    IV does not need to be secret.
    It must be unique for encryption.
    */

    aesIv =
        crypto.getRandomValues(
            new Uint8Array(12)
        );


    /*
    Convert message into bytes.
    */

    const encoder =
        new TextEncoder();

    const messageData =
        encoder.encode(message);


    /*
    Encrypt message using AES-GCM.
    */

    const encryptedData =
        await crypto.subtle.encrypt(

            {
                name: "AES-GCM",

                iv: aesIv
            },

            aesKey,

            messageData
        );


    return encryptedData;
}


// =====================================================
// RSA ENCRYPT AES KEY
// =====================================================

async function encryptAESKeyWithRSA() {

    /*
    Export AES key as raw bytes.
    */

    const rawAESKey =
        await crypto.subtle.exportKey(
            "raw",
            aesKey
        );


    /*
    Encrypt AES key using
    RSA public key.
    */

    const encryptedKey =
        await crypto.subtle.encrypt(

            {
                name: "RSA-OAEP"
            },

            rsaKeyPair.publicKey,

            rawAESKey
        );


    return encryptedKey;
}


// =====================================================
// MAIN ENCRYPT FUNCTION
// =====================================================

async function performEncryption() {

    try {

        const message =
            messageInput.value.trim();


        if (!message) {

            alert(
                "Please enter a message first."
            );

            return;
        }


        encryptBtn.disabled = true;

        encryptBtn.textContent =
            "⏳ Encrypting...";


        updateStatus(
            "Encrypting",
            "encrypted"
        );


        // ---------------------------------------------
        // STEP 1
        // AES encrypt message
        // ---------------------------------------------

        encryptedMessage =
            await encryptMessage(message);


        // ---------------------------------------------
        // STEP 2
        // RSA encrypt AES key
        // ---------------------------------------------

        encryptedAesKey =
            await encryptAESKeyWithRSA();


        // ---------------------------------------------
        // Display AES key
        // ---------------------------------------------

        const rawAESKey =
            await crypto.subtle.exportKey(
                "raw",
                aesKey
            );


        aesKeyOutput.value =
            arrayBufferToBase64(rawAESKey);


        // ---------------------------------------------
        // Display RSA encrypted AES key
        // ---------------------------------------------

        encryptedKeyOutput.value =
            arrayBufferToBase64(
                encryptedAesKey
            );


        // ---------------------------------------------
        // Display encrypted message
        //
        // IV is included before ciphertext.
        // ---------------------------------------------

        const ivAndCiphertext =
            new Uint8Array(
                aesIv.length +
                encryptedMessage.byteLength
            );


        ivAndCiphertext.set(
            aesIv,
            0
        );


        ivAndCiphertext.set(
            new Uint8Array(
                encryptedMessage
            ),
            aesIv.length
        );


        encryptedMessageOutput.value =
            arrayBufferToBase64(
                ivAndCiphertext
            );


        // ---------------------------------------------
        // Enable decryption
        // ---------------------------------------------

        decryptBtn.disabled = false;

        updateStatus(
            "Encrypted Successfully",
            "encrypted"
        );


        encryptBtn.textContent =
            "✓ Message Encrypted";


        console.log(
            "Encryption completed successfully."
        );

    }

    catch (error) {

        console.error(
            "Encryption error:",
            error
        );

        alert(
            "Encryption failed. Check the browser console."
        );

        updateStatus(
            "Encryption Failed",
            "ready"
        );

    }

    finally {

        encryptBtn.disabled = false;

    }
}


// =====================================================
// RSA DECRYPT AES KEY
// =====================================================

async function decryptAESKeyWithRSA() {

    /*
    Decrypt the RSA-encrypted AES key
    using the RSA private key.
    */

    const rawAESKey =
        await crypto.subtle.decrypt(

            {
                name: "RSA-OAEP"
            },

            rsaKeyPair.privateKey,

            encryptedAesKey
        );


    /*
    Convert the recovered bytes
    back into an AES-GCM CryptoKey.
    */

    const recoveredAESKey =
        await crypto.subtle.importKey(

            "raw",

            rawAESKey,

            {
                name: "AES-GCM"
            },

            false,

            [
                "decrypt"
            ]
        );


    return recoveredAESKey;
}


// =====================================================
// AES DECRYPT MESSAGE
// =====================================================

async function decryptMessage(recoveredAESKey) {

    /*
    Retrieve IV + ciphertext
    */

    const combinedData =
        new Uint8Array(
            base64ToUint8Array(
                encryptedMessageOutput.value
            )
        );


    /*
    First 12 bytes = AES IV
    */

    const iv =
        combinedData.slice(
            0,
            12
        );


    /*
    Remaining bytes = ciphertext
    */

    const ciphertext =
        combinedData.slice(
            12
        );


    /*
    Decrypt using recovered AES key.
    */

    const decryptedData =
        await crypto.subtle.decrypt(

            {
                name: "AES-GCM",

                iv: iv
            },

            recoveredAESKey,

            ciphertext
        );


    /*
    Convert bytes back to text.
    */

    const decoder =
        new TextDecoder();

    return decoder.decode(
        decryptedData
    );
}


// =====================================================
// MAIN DECRYPT FUNCTION
// =====================================================

async function performDecryption() {

    try {

        decryptBtn.disabled = true;

        decryptBtn.textContent =
            "⏳ Decrypting...";


        updateStatus(
            "Decrypting",
            "decrypted"
        );


        // ---------------------------------------------
        // STEP 1
        // RSA private key decrypts AES key
        // ---------------------------------------------

        const recoveredAESKey =
            await decryptAESKeyWithRSA();


        // ---------------------------------------------
        // STEP 2
        // AES decrypts the message
        // ---------------------------------------------

        const originalMessage =
            await decryptMessage(
                recoveredAESKey
            );


        // ---------------------------------------------
        // Display original message
        // ---------------------------------------------

        decryptedMessageOutput.textContent =
            originalMessage;


        updateStatus(
            "Decrypted Successfully",
            "decrypted"
        );


        decryptBtn.textContent =
            "✓ Message Decrypted";


        console.log(
            "Decryption completed successfully."
        );

    }

    catch (error) {

        console.error(
            "Decryption error:",
            error
        );

        alert(
            "Decryption failed. The encrypted data may be invalid."
        );

        updateStatus(
            "Decryption Failed",
            "ready"
        );

    }

    finally {

        decryptBtn.disabled = false;

    }
}


// =====================================================
// RESET
// =====================================================

async function resetApplication() {

    messageInput.value = "";

    clearOutputs();


    aesKey = null;

    aesIv = null;

    encryptedAesKey = null;

    encryptedMessage = null;


    decryptBtn.disabled = true;

    decryptBtn.textContent =
        "🔓 Decrypt Message";

    encryptBtn.textContent =
        "🔒 Encrypt Message";


    updateStatus(
        "Ready",
        "ready"
    );


    /*
    Generate a fresh RSA key pair
    after reset.
    */

    try {

        await generateRSAKeys();

    }

    catch (error) {

        console.error(
            "Could not regenerate RSA keys:",
            error
        );

    }

}


// =====================================================
// EVENT LISTENERS
// =====================================================

encryptBtn.addEventListener(
    "click",
    performEncryption
);

decryptBtn.addEventListener(
    "click",
    performDecryption
);

resetBtn.addEventListener(
    "click",
    resetApplication
);


// =====================================================
// APPLICATION STARTUP
// =====================================================

async function initializeApplication() {

    try {

        updateStatus(
            "Generating RSA Keys...",
            "encrypted"
        );

        await generateRSAKeys();

        updateStatus(
            "Ready",
            "ready"
        );

        console.log(
            "Secure Messaging App initialized."
        );

    }

    catch (error) {

        console.error(
            "Initialization error:",
            error
        );

        updateStatus(
            "Initialization Failed",
            "ready"
        );

        alert(
            "Your browser does not support the required Web Crypto API."
        );
    }
}


initializeApplication();
