package mytest;

import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class HelloController {
	
	@GetMapping("/hello-world")
	public String sayHello(HttpServletRequest request) {
		System.out.println("HELLO_WORLD");
		System.out.println(request.getParameter("name"));
		System.out.println(request.getParameter("value"));
		
		return "hello_world";
	}
	
	@GetMapping("/hello-test")
	public String testHello(
			@RequestParam("name") String name,
			@RequestParam("value") String value
	)
	{
		System.out.println("HELLO_TEST");
		System.out.println(name);
		System.out.println(value);
		
		return "hello_test";
	}
	
}
