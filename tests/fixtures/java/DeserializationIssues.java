// Test fixtures for Java deserialization vulnerabilities
import java.io.*;

public class DeserializationIssues {

    // Should trigger JAVA_DES001
    public Object deserializeObject(InputStream input) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(input);
        return ois.readObject();
    }

    // Should trigger JAVA_DES001
    public void readUnsharedExample(InputStream input) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(input);
        Object obj = ois.readUnshared();
    }

    // Should trigger JAVA_DES002 - missing serialVersionUID
    class User implements Serializable {
        private String username;
        private String email;

        public User(String username, String email) {
            this.username = username;
            this.email = email;
        }
    }
}
