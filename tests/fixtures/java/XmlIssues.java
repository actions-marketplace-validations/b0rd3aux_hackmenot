// Test fixtures for Java XXE vulnerabilities
import javax.xml.parsers.*;
import javax.xml.stream.*;
import org.w3c.dom.*;

public class XmlIssues {

    // Should trigger JAVA_XXE001
    public Document parseXmlWithDocumentBuilder(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(xml);
    }

    // Should trigger JAVA_XXE001
    public void parseXmlWithSAX(String xml) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        SAXParser parser = factory.newSAXParser();
    }

    // Should trigger JAVA_XXE001
    public void parseXmlWithStAX(String xml) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        XMLStreamReader reader = factory.createXMLStreamReader(xml);
    }
}
