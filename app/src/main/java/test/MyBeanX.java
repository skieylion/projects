package test;

import javax.enterprise.context.RequestScoped;
import javax.inject.Named;

@RequestScoped
@Named("newName")
public class MyBeanX {
	private String s = "hellow it is myBeanX";

	public String getS() {
		return s;
	}

	public void setS(String s) {
		this.s = s;
	}
	
	
}