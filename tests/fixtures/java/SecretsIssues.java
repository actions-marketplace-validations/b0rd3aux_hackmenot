// Test fixtures for hardcoded secrets in Java

public class SecretsIssues {

    // Should trigger JAVA_SEC001
    private static final String API_KEY = "sk-1234567890abcdef";
    private String password = "admin123";
    private String secret = "my-secret-key";
    private String accessKey = "AKIAIOSFODNN7EXAMPLE";

    public void connectToApi() {
        // Should trigger JAVA_SEC001
        String apiKey = "live_api_key_12345";
        String privateKey = "-----BEGIN PRIVATE KEY-----";

        makeApiCall(apiKey);
    }

    private void makeApiCall(String key) {
        // API call logic
    }
}
