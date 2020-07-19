package mytest;

import javax.annotation.Resource;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.servlet.http.HttpServletRequest;
import javax.transaction.Transactional;

import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import mytest.adapters.EventAdapter;
import mytest.entity.Event;
import mytest.service.impl.EventServiceImpl;

@Controller
public class HelloController {
	
	@Resource
	private EventServiceImpl event;
	
	
	@PersistenceContext
	EntityManager manager;
	
	
	
	
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
	
	@GetMapping("/home.jsp")
	public String sayIndex(HttpServletRequest request) {
		System.out.println("HELLO_INDEX");
		return "home.jsp";
	}
	
	@GetMapping("/events")
	public String events(HttpServletRequest request) {
		return "events";
	}
	@GetMapping("/create-event")
	public String createEvents(HttpServletRequest request) {
		return "create_event";
	}
	
	@Transactional
	@ResponseBody
	@PostMapping(path="/create-task",consumes = MediaType.APPLICATION_JSON_VALUE,produces=MediaType.APPLICATION_JSON_VALUE)
	public String createTask(@RequestBody EventAdapter ea) {
		System.out.println("CREATE-TASK");
		System.out.println(ea);
		System.out.println(ea.getDescriptionTask());
		System.out.println(ea.getNameTask());
		Event e=new Event();
		e.setName(ea.getNameTask());
		e.setDescription(ea.getDescriptionTask());
		Session session=(Session) manager.unwrap(Session.class);
		//session.beginTransaction();
		SessionFactory sf=session.getSessionFactory();
		sf.openSession();
		event.add(e);

		//System.out.println(event.getById(1).getName());
		//sf.close();
		
		
		return "true";
	}
}
