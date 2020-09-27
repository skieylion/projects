package simpleapp.mysimple;

import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;


@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
	"key1",
	"key2"
})
public class RootName {
	@JsonProperty("key1")
	@JsonPropertyDescription("An explanation about the purpose of this instance.")
	/*@JacksonXmlProperty(
		isAttribute = true, 
		namespace = "urn:stackify:jacksonxml" 
	)*/
	@JacksonXmlProperty(namespace = "urn:stackify:jackson")
	private Integer key1 = 0;
	
	@JsonProperty("key2")
	@JsonPropertyDescription("An explanation about the purpose of this instance.")
	private String key2 = "";
	@JsonIgnore
	private Map<String, Object> additionalProperties = new HashMap<String, Object>();
	
	@JsonProperty("key1")
	public Integer getKey1() {
	return key1;
	}
	
	@JsonProperty("key1")
	public void setKey1(Integer key1) {
	this.key1 = key1;
	}
	
	@JsonProperty("key2")
	public String getKey2() {
	return key2;
	}
	
	@JsonProperty("key2")
	public void setKey2(String key2) {
		this.key2 = key2;
	}
	
	@JsonAnyGetter
	public Map<String, Object> getAdditionalProperties() {
		return this.additionalProperties;
	}
	
	@JsonAnySetter
	public void setAdditionalProperty(String name, Object value) {
		this.additionalProperties.put(name, value);
	}

}
