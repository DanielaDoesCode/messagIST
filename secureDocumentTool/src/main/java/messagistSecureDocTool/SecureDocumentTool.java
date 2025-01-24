package messagistSecureDocTool;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import messagistSecureDoc.SecureDocument;

public class SecureDocumentTool {

    private static final String SIGN_CIPHER_ALGO = "RSA";

    public static void main(String[] args) {
        // Check arguments
        if (args.length < 1) {
            System.err.println("Argument(s) missing!");
            printUsage();
            return;
        }

        final String command = args[0];

        if (command.equals("protect")) {
            protect(args);
        } else if (command.equals("check")) {
            check(args);
        } else if (command.equals("unprotect")) {
            unprotect(args);
        } else if (command.equals("help")) {
            help();
        } else {
            printUsage();
            return;
        }
    }

    private static void printUsage() {
        System.err.printf("Enter 'java %s help' to get a list of available commands%n",
                SecureDocumentTool.class.getName());
    }

    private static void protect(String[] args) {
        if (args.length < 4) {
            System.err.println("Argument(s) missing!");
            System.err.printf("Usage: java %s protect (input-file) (recipient-public-key) (sender-private-key) (sender-public-key) (output-file)%n",
                    SecureDocumentTool.class.getName());
            return;
        }

        final String inputFilename = args[1];
        final String recipientKeyFilename = args[2];
        final String senderPrivateKeyFilename = args[3];
        final String senderPublicKeyFilename = args[4];
        final String outputFilename = args[5];

        Path inputFilepath = Paths.get(inputFilename);
        Path outputFilepath = Paths.get(outputFilename);
        try {
            String inputContent = Files.readString(inputFilepath);
            SecureDocument document = new SecureDocument(inputContent);
            PublicKey recipientKey = readPublicKey(recipientKeyFilename);
            PrivateKey senderPrivateKey = readPrivateKey(senderPrivateKeyFilename);
            PublicKey senderPublicKey = readPublicKey(senderPublicKeyFilename);
            document.protect(recipientKey, senderPrivateKey, senderPublicKey);
            Files.writeString(outputFilepath, document.getMessage());
        } catch (IOException e) {
            System.err.printf("Error loading file: %s%n", e.getMessage());
        } catch (Exception e) {
            System.err.printf("Error: %s%n", e.getMessage());
        }
    }

    private static void check(String[] args) {
        if (args.length < 3) {
            System.err.println("Argument(s) missing!");
            System.err.printf("Usage: java %s check (input-file) (sender-public-key)%n",
                    SecureDocumentTool.class.getName());
            return;
        }

        final String inputFilename = args[1];
        final String senderKeyFilename = args[2];

        Path inputFilepath = Paths.get(inputFilename);
        try {
            String inputContent = Files.readString(inputFilepath);
            SecureDocument document = new SecureDocument(inputContent);
            PublicKey senderKey = readPublicKey(senderKeyFilename);
            boolean valid = document.check(senderKey);
            if (valid) {
                System.out.println("Signature matches! Message contents are valid.");
            }
            else {
                System.out.println("Signature mismatch! Message contents may have been tampered with or corrupted.");
            }
        } catch (IOException e) {
            System.err.printf("Error loading file: %s%n", e.getMessage());
        } catch (Exception e) {
            System.err.printf("Error: %s%n", e.getMessage());
        }
    }

    private static void unprotect(String[] args) {
        if (args.length < 4) {
            System.err.println("Argument(s) missing!");
            System.err.printf("Usage: java %s unprotect (input-file) (recipient-private-key) (sender-public-key) (use-sender-key - true|false) (output-file)%n",
                    SecureDocumentTool.class.getName());
            return;
        }

        final String inputFilename = args[1];
        final String recipientKeyFilename = args[2];
        final String senderKeyFilename = args[3];
        final String useSenderKeyString = args[4];
        final String outputFilename = args[5];

        Path inputFilepath = Paths.get(inputFilename);
        Path outputFilepath = Paths.get(outputFilename);
        try {
            String inputContent = Files.readString(inputFilepath);
            SecureDocument document = new SecureDocument(inputContent);
            PrivateKey recipientKey = readPrivateKey(recipientKeyFilename);
            PublicKey senderKey = readPublicKey(senderKeyFilename);
            boolean useSenderKey = Boolean.parseBoolean(useSenderKeyString);
            document.unprotect(recipientKey, senderKey, useSenderKey);
            Files.writeString(outputFilepath, document.getMessage());
        } catch (IOException e) {
            System.err.printf("Error loading file: %s%n", e.getMessage());
        } catch (Exception e) {
            System.err.printf("Error: %s%n", e.getMessage());
        }
    }

    private static void help() {
        System.out.println("Usage:");

        System.out.printf("java %s protect (input-file) (recipient-public-key) (sender-private-key) (sender-public-key) (output-file)%n",
                SecureDocumentTool.class.getName());
        System.out.println("\tEncrypt the contents of a message in (input-file) using an AES key encrypted with (recipient-public-key) and (sender-public-key), sign using RSA (sender-private-key), and store the result in (output-file).");

        System.out.printf("java %s check (input-file) (sender-public-key)%n",
                SecureDocumentTool.class.getName());
        System.out.println("\tCheck the integrity of the contents of a message in (input-file) encrypted with AES and signed with RSA (sender-public-key).");

        System.out.printf("java %s unprotect (input-file) (recipient-private-key) (sender-public-key) (use-sender-key - true|false) (output-file)%n",
                SecureDocumentTool.class.getName());
        System.out.println("\tDecrypt the contents of a message in (input-file) using an AES key encrypted with (recipient-private-key), verify signature using RSA (sender-public-key), and store the result in (output-file). " +
            "If (use-sender-key) is true, assume the sender is reading the message and (recipient-private-key) is the sender's private key.");

        System.out.printf("java %s help%n",
                SecureDocumentTool.class.getName());
        System.out.println("\tDisplay this message.");
    }

    private static byte[] readFile(String path) throws FileNotFoundException, IOException {
        FileInputStream fis = new FileInputStream(path);
        byte[] content = new byte[fis.available()];
        fis.read(content);
        fis.close();
        return content;
    }

    public static PrivateKey readPrivateKey(String privateKeyPath) throws Exception {
        byte[] privEncoded = readFile(privateKeyPath);
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privEncoded);
        KeyFactory keyFacPriv = KeyFactory.getInstance(SIGN_CIPHER_ALGO);
        PrivateKey priv = keyFacPriv.generatePrivate(privSpec);
        return priv;
    }

    public static PublicKey readPublicKey(String publicKeyPath) throws Exception {
        byte[] pubEncoded = readFile(publicKeyPath);
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubEncoded);
        KeyFactory keyFacPub = KeyFactory.getInstance(SIGN_CIPHER_ALGO);
        PublicKey pub = keyFacPub.generatePublic(pubSpec);
        return pub;
    }
}
