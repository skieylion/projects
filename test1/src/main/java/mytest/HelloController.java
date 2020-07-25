package mytest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.Resource;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.servlet.http.HttpServletRequest;
import javax.transaction.Transactional;

import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;
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
import mytest.adapters.HeaderMetro;
import mytest.adapters.HeaderMetroJson;
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
	@GetMapping("/deleteTask")
	public String testHello(
			@RequestParam("id") Long _id
	)
	{
		Session session=(Session) manager.unwrap(Session.class);
		SessionFactory sf=session.getSessionFactory();
		sf.openSession();
		event.remove(_id);
		
		return "true";
	}
	
	
	@Transactional
	@ResponseBody
	@PostMapping(path="/create-task",consumes = MediaType.APPLICATION_JSON_VALUE,produces=MediaType.APPLICATION_JSON_VALUE)
	public String createTask(@RequestBody EventAdapter ea) {
		Event e=new Event();
		e.setName(ea.getNameTask());
		e.setDescription(ea.getDescriptionTask());
		e.setDueDate(ea.getDueDateTask());
		Session session=(Session) manager.unwrap(Session.class);
		SessionFactory sf=session.getSessionFactory();
		sf.openSession();
		event.add(e);

		//sf.close();
				
		return "true";
	}
	
	@Transactional
	@ResponseBody
	@GetMapping(path="/get-tasks",produces=MediaType.APPLICATION_JSON_VALUE)
	public String getTasks(HttpServletRequest request) throws JsonGenerationException, JsonMappingException, IOException {
		Session session=(Session) manager.unwrap(Session.class);
		SessionFactory sf=session.getSessionFactory();
		sf.openSession();
		List<Event> listEvents=event.getAll();
		List<HeaderMetro> listHM=new ArrayList<HeaderMetro>();
		HeaderMetro hmName=new HeaderMetro();
		hmName.setTitle("Название");
		hmName.setSortable(true);
		HeaderMetro hmDescription=new HeaderMetro();
		hmDescription.setTitle("Описание");
		hmDescription.setSortable(true);
		HeaderMetro hmDueDate=new HeaderMetro();
		hmDueDate.setTitle("Срок выполнения");
		hmDueDate.setSortable(true);
		HeaderMetro hmID=new HeaderMetro();
		hmID.setTitle("ID");
		hmID.setSortable(true);
		hmID.setShow(false);
		
		listHM.add(hmName);
		listHM.add(hmDescription);
		listHM.add(hmDueDate);
		listHM.add(hmID);
		
		List<List<String>> dataJ=new ArrayList<List<String>>();
		
		for(int i=0;i<listEvents.size();i++) {
			Event edata=listEvents.get(i);
			List<String> l=new ArrayList<String>();
			l.add(edata.getName());
			l.add(edata.getDescription());
			SimpleDateFormat d = new SimpleDateFormat("MM-dd-yyyy");
			l.add(d.format(edata.getDueDate()));
			Long ID=edata.getId();
			l.add(ID.toString());
			dataJ.add(l);
			
		}
		
		HeaderMetroJson hmj=new HeaderMetroJson();
		hmj.setHeader(listHM);
		hmj.setData(dataJ);
		
		ObjectMapper mapper=new ObjectMapper();
		final ByteArrayOutputStream out = new ByteArrayOutputStream();
		mapper.writeValue(out, hmj);
		final byte[] data = out.toByteArray();

		return new String(data);
	}
}
