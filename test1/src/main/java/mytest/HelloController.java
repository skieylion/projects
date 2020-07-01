package mytest;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HelloController {
	@GetMapping("/hello-world")
	public String sayHello() {
		System.out.println("HELLO_WORLD");
		return "hello_world";
	}
}
