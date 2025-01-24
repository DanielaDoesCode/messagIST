package client;

import java.io.IOException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;


public class PasswordDerivationService {

    private final String masterPassword;
    private final String salt;
    private KeyPair keyPair;

    private static final String CIPHER_TRANSFORMATION = "RSA";
    private static final String KEY_FACTORY_ALGORITHM = "PBKDF2WithHmacSHA256";

    public PasswordDerivationService(String masterPassword, String salt)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
            
        this.masterPassword = masterPassword;
        this.salt = salt;
    }

    public SecretKey deriveSecretKey()
        throws NoSuchAlgorithmException, InvalidKeySpecException {

        // Generate a secret key using PBKDF2
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_FACTORY_ALGORITHM);
        final int keyLength = 256;
        PBEKeySpec spec = new PBEKeySpec(masterPassword.toCharArray(), salt.getBytes(), 10000, keyLength);
        SecretKey secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

        return secretKey;
    }

    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {

        SecureRandom secureRandom = new SecureRandom();

        // Generate key pair
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CIPHER_TRANSFORMATION);
        final int asymKeyLength = 2048;
		keyGen.initialize(asymKeyLength, secureRandom);

		return keyGen.generateKeyPair();
    }

    public String encryptPrivateKey(PrivateKey privateKey, SecretKey secretKey) throws Exception {

        // cipher data
        Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] keyCipherBytes = cipher.doFinal(privateKey.getEncoded());

        return Base64.getEncoder().encodeToString(keyCipherBytes);
    }

    public PrivateKey decryptPrivateKey(String receivedPrivateKey, SecretKey secretKey) throws Exception {

        // cipher data
        Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] privEncoded = cipher.doFinal(Base64.getDecoder().decode(receivedPrivateKey));

        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privEncoded);
        KeyFactory keyFacPriv = KeyFactory.getInstance(CIPHER_TRANSFORMATION);
        PrivateKey priv = keyFacPriv.generatePrivate(privSpec);
        return priv;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }
}