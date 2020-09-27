package simpleapp.mysimple;

import javax.xml.bind.JAXBElement;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationModule;
import model.CustomerNotifyStatus;
import model.ObjectFactory;
/**
 * Hello world!
 *
 */
public class App 
{
	static String jsonString = "{\"rootName\":{\"key1\":1,\"key2\":\"asd\"}}";
	public static void main( String[] args ) throws JsonProcessingException
    {
    	ObjectMapper objectMapper=new ObjectMapper();
    	Example ex = objectMapper.readValue(jsonString, Example.class);
    	XmlMapper xmlMapper = new XmlMapper();
    	String xml = xmlMapper.writeValueAsString(ex);
    	//ObjectMapper xmlMapper = new XmlMapper();
		//Example ex=xmlMapper.readValue("<SimpleBean><x>1</x><y>2</y></SimpleBean>", SimpleBean.class);
		//JsonNode tree = objectMapper.readTree(jsonString);
		//String jsonAsXml = xmlMapper.writer().withRootName("RootName").writeValueAsString(tree);
		
    	System.out.println(xml);
    }
}
