// Test fixtures for Java cryptography issues
import java.security.*;
import java.util.Random;

public class CryptoIssues {

    // Should trigger JAVA_CRY001
    public void weakMd5Hash(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        byte[] hash = digest.digest(data);
    }

    // Should trigger JAVA_CRY001
    public void weakSha1Hash(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        byte[] hash = digest.digest(data);
    }

    // Should trigger JAVA_CRY002
    public long generateSessionId() {
        Random random = new Random();
        return random.nextLong();
    }

    // Should trigger JAVA_CRY002
    public String generateToken() {
        Random random = new Random();
        return String.valueOf(random.nextInt());
    }
}
