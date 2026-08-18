let rsaKeyPair = null;
let aesKey = null;
let encryptedMessageData = null;
let encryptedAesKey = null;

const messageInput = document.getElementById("messageInput");
const encryptBtn = document.getElementById("encryptBtn");
const decryptBtn = document.getElementById("decryptBtn");

const aesKeyBox = document.getElementById("aesKey");
const encryptedMessageBox = document.getElementById("encryptedMessage");
const encryptedKeyBox = document.getElementById("encryptedKey");

const rsaStatus = document.getElementById("rsaStatus");
const aesStatus = document.getElementById("aesStatus");
const decryptedMessage = document.getElementById("decryptedMessage");

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";

    bytes.forEach(byte => {
        binary += String.fromCharCode(byte);
    });

    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes.buffer;
}

async function generateRSAKeys() {

    rsaKeyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256"
        },
        true,
        ["encrypt", "decrypt"]
    );
}

async function encryptMessage() {

    const message = messageInput.value.trim();

    if (!message) {
        alert("Please enter a message first.");
        return;
    }

    try {

        encryptBtn.disabled = true;
        encryptBtn.textContent = "Encrypting...";

        if (!rsaKeyPair) {
            await generateRSAKeys();
        }

        aesKey = await window.crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );

        const rawAesKey = await window.crypto.subtle.exportKey(
            "raw",
            aesKey
        );

        const aesKeyBase64 = arrayBufferToBase64(rawAesKey);

        aesKeyBox.textContent =
            aesKeyBase64 +
            "\n\nKey Size: 256 bits\nEncoding: Base64";

        const encoder = new TextEncoder();
        const messageData = encoder.encode(message);

        const iv = window.crypto.getRandomValues(
            new Uint8Array(12)
        );

        const encryptedMessage = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            aesKey,
            messageData
        );

        const encryptedMessageBase64 =
            arrayBufferToBase64(encryptedMessage);

        const ivBase64 = arrayBufferToBase64(iv);

        encryptedMessageData = {
            ciphertext: encryptedMessageBase64,
            iv: ivBase64
        };

        encryptedMessageBox.textContent =
            "IV:\n" +
            ivBase64 +
            "\n\nCiphertext:\n" +
            encryptedMessageBase64;

        encryptedAesKey = await window.crypto.subtle.encrypt(
            {
                name: "RSA-OAEP"
            },
            rsaKeyPair.publicKey,
            rawAesKey
        );

        const encryptedKeyBase64 =
            arrayBufferToBase64(encryptedAesKey);

        encryptedKeyBox.textContent =
            encryptedKeyBase64 +
            "\n\nAlgorithm: RSA-OAEP\nRSA Key Size: 2048 bits";

        rsaStatus.textContent =
            "✓ AES key encrypted using RSA public key";

        rsaStatus.style.color = "#86efac";

        aesStatus.textContent =
            "✓ AES-256 encrypted ciphertext generated";

        aesStatus.style.color = "#86efac";

        decryptBtn.disabled = false;

        decryptedMessage.textContent =
            "Encrypted successfully. Click \"Decrypt Message\".";

    } catch (error) {

        console.error(error);

        alert(
            "Encryption failed: " +
            error.message
        );

    } finally {

        encryptBtn.disabled = false;
        encryptBtn.textContent = "🔒 Encrypt Message";

    }
}

async function decryptMessage() {

    try {

        decryptBtn.disabled = true;
        decryptBtn.textContent = "Decrypting...";

        const recoveredAesKeyBuffer =
            await window.crypto.subtle.decrypt(
                {
                    name: "RSA-OAEP"
                },
                rsaKeyPair.privateKey,
                encryptedAesKey
            );

        rsaStatus.textContent =
            "✓ RSA private key successfully recovered AES key";

        rsaStatus.style.color = "#86efac";

        const recoveredAesKey =
            await window.crypto.subtle.importKey(
                "raw",
                recoveredAesKeyBuffer,
                {
                    name: "AES-GCM"
                },
                false,
                ["decrypt"]
            );

        const ciphertext =
            base64ToArrayBuffer(
                encryptedMessageData.ciphertext
            );

        const iv =
            new Uint8Array(
                base64ToArrayBuffer(
                    encryptedMessageData.iv
                )
            );

        const decryptedData =
            await window.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: iv
                },
                recoveredAesKey,
                ciphertext
            );

        const decoder = new TextDecoder();

        const originalMessage =
            decoder.decode(decryptedData);

        aesStatus.textContent =
            "✓ AES-256 successfully decrypted the message";

        aesStatus.style.color = "#86efac";

        decryptedMessage.textContent =
            originalMessage;

        decryptBtn.textContent =
            "✓ Message Decrypted";

    } catch (error) {

        console.error(error);

        alert(
            "Decryption failed: " +
            error.message
        );

        decryptBtn.disabled = false;
        decryptBtn.textContent =
            "🔓 Decrypt Message";
    }
}

encryptBtn.addEventListener(
    "click",
    encryptMessage
);

decryptBtn.addEventListener(
    "click",
    decryptMessage
);

window.addEventListener(
    "load",
    async () => {

        try {

            await generateRSAKeys();

        } catch (error) {

            console.error(
                "RSA key generation failed:",
                error
            );

        }

    }
);