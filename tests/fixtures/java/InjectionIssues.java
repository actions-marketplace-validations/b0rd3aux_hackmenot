// Test fixtures for Java injection vulnerabilities
import java.sql.*;
import java.io.IOException;

public class InjectionIssues {

    // Should trigger JAVA_INJ001
    public void sqlInjection(Connection conn, String userId) throws SQLException {
        String query = "SELECT * FROM users WHERE id = " + userId;
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);
    }

    // Should trigger JAVA_INJ001
    public void sqlInjectionWithConcat(Connection conn, String username) throws SQLException {
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        Statement stmt = conn.createStatement();
        stmt.executeQuery(query);
    }

    // Should trigger JAVA_INJ002
    public void commandInjectionRuntime(String userInput) throws IOException {
        Runtime.getRuntime();
    }

    // Should trigger JAVA_INJ002
    public void commandInjectionProcessBuilder(String path) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("cat", path);
    }
}
