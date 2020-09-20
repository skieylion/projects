package simplews;

import javax.jws.WebService;

@WebService(endpointInterface="simplews.HelloWebService")
public class HelloWebServiceImpl implements HelloWebService {
	@Override
	public String getHelloString(String name) {
		return "Hello "+name;
	}
}
