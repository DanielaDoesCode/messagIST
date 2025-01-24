package messagistSecureDoc;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.google.gson.*;

public class SecureDocument {

    /** Message authentication code algorithm. */
    private static final String SIGN_CIPHER_ALGO = "SHA256withRSA";
    private static final String CIPHER_ALGO = "AES";
    private static final int AES_SIZE = 128;
    private static final String ASYM_CIPHER_ALGO = "RSA";

    private JsonObject jsonObject;

    public SecureDocument(String message) {
        this.jsonObject = JsonParser.parseString(message).getAsJsonObject();
    }

    public String getMessage() {
        return jsonObject.toString();
    }

    public void protect(PublicKey recipientKey, PrivateKey senderPrivateKey, PublicKey senderPublicKey) throws Exception {
        // Generate random secret key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_SIZE);
        SecretKey key = keyGen.generateKey();

        // Encrypt plain text
        String content = getMessageContent();
        byte[] cipherBytes = encryptMessage(content, key);
        setMessageContent(Base64.getEncoder().encodeToString(cipherBytes));

        // Encrypt secret key
        byte[] keyForReceiverCipherBytes = encryptSecretKey(key, recipientKey);
        byte[] keyForSenderCipherBytes = encryptSecretKey(key, senderPublicKey);
        addKeys(keyForReceiverCipherBytes, keyForSenderCipherBytes);

        // Compute signature of cipher text
        byte[] signatureBytes = makeDigitalSignature(cipherBytes, senderPrivateKey);
        addSignature(signatureBytes);
    }

    public boolean check(PublicKey senderKey) throws Exception {
        byte[] messageBytes = Base64.getDecoder().decode(getMessageContent());
        byte[] signatureBytes = getSignature();

        // Verify signature
        return verifyDigitalSignature(messageBytes, signatureBytes, senderKey);
    }

    public void unprotect(PrivateKey recipientKey, PublicKey senderKey, boolean useSenderKey) throws Exception {
        byte[] messageBytes = Base64.getDecoder().decode(getMessageContent());
        byte[] signatureBytes = getSignature();

        // Verify signature
        if (!verifyDigitalSignature(messageBytes, signatureBytes, senderKey)) {
            throw new Exception("Signature mismatch! Message contents may have been tampered with or corrupted.");
        }

        // Decrypt secret key
        byte[] keyBytes;
        if (useSenderKey) {
            // Assume recipientKey is actually the sender's private key
            byte[] keyCipherBytes = getKeyForSender();
            keyBytes = decryptSecretKey(keyCipherBytes, recipientKey);
        }
        else {
            byte[] keyCipherBytes = getKeyForReceiver();
            keyBytes = decryptSecretKey(keyCipherBytes, recipientKey);
        }
        SecretKey key = new SecretKeySpec(keyBytes, 0, keyBytes.length, CIPHER_ALGO);

        // Decrypt text
        byte[] plaintextBytes = decryptMessage(messageBytes, key);
        setMessageContent(new String(plaintextBytes));

        removeSignature();
        removeKeys();
    }


    private JsonObject getMessageObject() {
        JsonObject messageObject = jsonObject.get("message").getAsJsonObject();
        return messageObject;
    }

    private String getMessageContent() {
        JsonObject messageObject = getMessageObject();
        return messageObject.get("content").getAsString();
    }

    private void setMessageContent(String content) {
        JsonObject messageObject = getMessageObject();
        messageObject.addProperty("content", content);
    }

    private void addKeys(byte[] keyForReceiverCipherBytes, byte[] keyForSenderCipherBytes) {
        JsonObject messageObject = getMessageObject();
        messageObject.addProperty("keyForReceiver", Base64.getEncoder().encodeToString(keyForReceiverCipherBytes));
        messageObject.addProperty("keyForSender", Base64.getEncoder().encodeToString(keyForSenderCipherBytes));
    }

    private byte[] getKeyForReceiver() {
        JsonObject messageObject = getMessageObject();
        return Base64.getDecoder().decode(messageObject.get("keyForReceiver").getAsString());
    }

    private byte[] getKeyForSender() {
        JsonObject messageObject = getMessageObject();
        return Base64.getDecoder().decode(messageObject.get("keyForSender").getAsString());
    }

    private void removeKeys() {
        JsonObject messageObject = getMessageObject();
        messageObject.remove("keyForReceiver");
        messageObject.remove("keyForSender");
    }

    private void addSignature(byte[] signatureBytes) {
        JsonObject messageObject = getMessageObject();
        messageObject.addProperty("signature", Base64.getEncoder().encodeToString(signatureBytes));
    }

    private byte[] getSignature() {
        JsonObject messageObject = getMessageObject();
        return Base64.getDecoder().decode(messageObject.get("signature").getAsString());
    }

    private void removeSignature() {
        JsonObject messageObject = getMessageObject();
        messageObject.remove("signature");
    }

    /**
     * Calculates new digest from text and compares it to the to deciphered digest.
     */
    private static boolean verifyDigitalSignature(byte[] messageBytes, byte[] signatureBytes, PublicKey signingkey)
            throws Exception {

        // verify the signature with the public key
        Signature sig = Signature.getInstance(SIGN_CIPHER_ALGO);
        sig.initVerify(signingkey);
        sig.update(messageBytes);
        try {
            return sig.verify(signatureBytes);
        } catch (SignatureException se) {
            System.err.println("Caught exception while verifying " + se);
            return false;
        }
    }

    /** Calculates digital signature from text. */
    private static byte[] makeDigitalSignature(byte[] bytes, PrivateKey signingKey) throws Exception {

        // get a signature object and sign the plain text with the private key
        Signature sig = Signature.getInstance(SIGN_CIPHER_ALGO);
        sig.initSign(signingKey);
        sig.update(bytes);
        byte[] signature = sig.sign();

        return signature;
    }

    private static byte[] encryptMessage(String message, SecretKey key) throws Exception
    {
        // cipher data
        Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherBytes = cipher.doFinal(message.getBytes());

        return cipherBytes;
    }

    private static byte[] decryptMessage(byte[] cipherBytes, SecretKey key) throws Exception
    {
        // decipher data
        Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] messageBytes = cipher.doFinal(cipherBytes);

        return messageBytes;
    }

    private static byte[] encryptSecretKey(SecretKey key, PublicKey recipientKey) throws Exception
    {
        // cipher data
        Cipher cipher = Cipher.getInstance(ASYM_CIPHER_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, recipientKey);
        byte[] keyCipherBytes = cipher.doFinal(key.getEncoded());

        return keyCipherBytes;
    }

    private static byte[] decryptSecretKey(byte[] keyCipherBytes, PrivateKey recipientKey) throws Exception
    {
        // decipher data
        Cipher cipher = Cipher.getInstance(ASYM_CIPHER_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, recipientKey);
        byte[] keyBytes = cipher.doFinal(keyCipherBytes);

        return keyBytes;
    }
}
