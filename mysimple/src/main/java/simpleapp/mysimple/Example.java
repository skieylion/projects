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
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;


@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
	"rootName"
})
@JacksonXmlRootElement(namespace = "urn:stackify:jacksonxml", localName = "PersonData")
public class Example {

	@JsonProperty("rootName")
	@JsonPropertyDescription("An explanation about the purpose of this instance.")
	private RootName rootName;
	@JsonIgnore
	private Map<String, Object> additionalProperties = new HashMap<String, Object>();

	@JsonProperty("rootName")
	public RootName getRootName() {
		return rootName;
	}

	@JsonProperty("rootName")
	public void setRootName(RootName rootName) {
		this.rootName = rootName;
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



