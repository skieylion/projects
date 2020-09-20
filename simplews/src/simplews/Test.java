package simplews;

import javax.xml.ws.Endpoint;

public class Test {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		Endpoint.publish("http://localhost:1986/wss", new HelloWebServiceImpl());
		System.out.println(1);
	}

}
