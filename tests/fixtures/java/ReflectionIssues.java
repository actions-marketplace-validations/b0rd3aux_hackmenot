// Test fixtures for Java reflection vulnerabilities
import java.lang.reflect.*;

public class ReflectionIssues {

    // Should trigger JAVA_REF001
    public Object loadClass(String className) throws Exception {
        Class<?> clazz = Class.forName(className);
        return clazz.newInstance();
    }

    // Should trigger JAVA_REF001
    public Object invokeMethod(String className, String methodName) throws Exception {
        Class<?> clazz = Class.forName(className);
        Method method = clazz.getMethod(methodName);
        return method.invoke(null);
    }

    // Should trigger JAVA_REF001
    public Object createInstance(String className) throws Exception {
        Class<?> clazz = Class.forName(className);
        Constructor<?> constructor = clazz.getConstructor();
        return constructor.newInstance();
    }
}
