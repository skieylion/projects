package test;

import java.io.IOException;
import java.io.Serializable;
import java.lang.annotation.Retention;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.decorator.Decorator;
import javax.decorator.Delegate;
import javax.ejb.Remove;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.Conversation;
import javax.enterprise.context.ConversationScoped;
import javax.enterprise.context.Dependent;
import javax.enterprise.context.RequestScoped;
import javax.enterprise.context.SessionScoped;
import javax.enterprise.event.Event;
import javax.enterprise.event.Observes;
import javax.enterprise.inject.Alternative;
import javax.enterprise.inject.Disposes;
import javax.enterprise.inject.Produces;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Qualifier;
import javax.inject.Singleton;
import javax.interceptor.AroundConstruct;
import javax.interceptor.AroundInvoke;
import javax.interceptor.ExcludeClassInterceptors;
import javax.interceptor.Interceptor;
import javax.interceptor.Interceptors;
import javax.interceptor.InterceptorBinding;
import javax.interceptor.InvocationContext;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.annotation.*;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * Servlet implementation class MyServlet
 */
@WebServlet("/MyServlet")
public class MyServlet extends HttpServlet {
	
	//скоуп бинов
	@Inject
	public MyBean1 mb;
	
	@Inject
	public ChangeMyBean cmb;
	
	//injection point
	@Inject
	Logger logger;
	
	@Inject
	@StudentAnnotation
	Person s;
	
	@Inject
	@WorkerAnnotation
	Person w;
	
	@Inject
	Transport t;
	
	@Inject
	@ProducesS1
	String s1;
	
	@Inject
	@ProducesS2
	String s2;
	
	@Inject
	Integer i;
	
	@Inject
	Double d;
	
	@Inject
	Engine e;
	
	@Inject
	ConversationBean cb;
	
	
	//@Inject
	//MDB1 mdb_1;
	
	//@Inject
	//MDB2 mdb_2;
	
	@Inject
	MyBeanX myBeanX;
	
	//@Inject
	//LifeCycleBean lfb;
	
	//@Inject
	//IBean ibean;
	
	@Inject
	IBeanChain ibchain;
	
	@Inject
	Parent p;
	
	@Inject
	BookService bookService;
	
	@Inject
	Subscriber sub;
	
	private static final long serialVersionUID = 1L;

    /**
     * Default constructor. 
     */
    public MyServlet() {
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		Book one=new Book("one");
		bookService.addBook(one);
		bookService.addBook(new Book("two"));
		bookService.addBook(new Book("three"));
		bookService.removeBook(one);
		
		
		//p.print();
		
		//ibchain.doJob();
		//lfb.doJob();
		//lfb.doJob2();
		
		//ibean.doJob();
		//ibean.doJob2();
		
		cb.i=3;
		System.out.println(cb.i);
		cb.startConversation();
		cb.i=4;
		System.out.println(cb.i);
		cb.endConversation();
		cb.i=5;
		System.out.println(cb.i);
		
		logger.log(Level.ALL,"logger message : GET_0");
		
		mb.i=5;
		cmb.changeBean();
		
		logger.log(Level.ALL,"myBean: "+mb.i+"; changeMyBean: "+cmb.b.i);
		
		//mdb_1.onMessage("GET_1");
		//mdb_2.onMessage("GET_2");
		
		// TODO Auto-generated method stub
		System.out.println(s);
		System.out.println(w);
		System.out.println(t.getName());
		System.out.println("--------------");
		System.out.println(s1);
		System.out.println(s2);
		System.out.println(i);
		System.out.println(d);
		System.out.println(e.name);
		
		RequestDispatcher dispatcher=request.getRequestDispatcher("/index.jsp");
		//dispatcher.forward(request, response);
		
		//response.getWriter().append("Served at: ").append(request.getContextPath()).append("sd");
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		doGet(request, response);
	}

}


@Qualifier
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD,ElementType.TYPE,ElementType.METHOD})
@interface StudentAnnotation {};

@Qualifier
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD,ElementType.TYPE,ElementType.METHOD})
@interface WorkerAnnotation {};

interface Person {
	String getName();
}

@StudentAnnotation
class Student implements Person {
	private String name;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
}

@WorkerAnnotation
class Worker implements Person {
	private String name;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
}

interface Transport {
	String getName();
}

class Car implements Transport {
	public String getName() {
		return "Auto";
	}
}

@Alternative
class Plane implements Transport {
	public String getName() {
		return "Plane";
	}
}

@Qualifier
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD,ElementType.TYPE,ElementType.METHOD})
@interface ProducesS2 {};
@Qualifier
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD,ElementType.TYPE,ElementType.METHOD})
@interface ProducesS1 {};
class Producers {
	@Produces
	@ProducesS1
	String s1="str 1";
	@Produces
	@ProducesS2
	String s2="str 2";
	@Produces
	Integer i=1;
	@Produces
	public Double getDouble() {
		return 2.3;
	}
	
	@Produces
	public Engine getEngine() {
		return new Engine("Engine");
	}
	
	public void Clear(@Disposes Engine e) {
		e.Clear();
	}
	
	//injection point
	@Produces
	public Logger getLogger(InjectionPoint inPoint) {
		Handler h=new ConsoleHandler();
		h.setLevel(Level.ALL);
		Logger l=Logger.getLogger(inPoint.getMember().getDeclaringClass().getName());
		l.addHandler(h);
		l.setLevel(Level.ALL);
		l.setUseParentHandlers(false);
		return l;
	}
}


class Engine {
	public String name;
	public Engine(String name) {
		this.name=name;
	}
	public void Clear() {
		System.out.println("Clear "+name);
	}
}

//скоуп бинов

//@ApplicationScoped
//@SessionScoped
//@ConversationScoped
//@Dependent

@RequestScoped
class MyBean1 {
	int i;
}

class ChangeMyBean {
	@Inject
	public MyBean1 b;
	
	public void changeBean() {
		b.i=2;
	}
}

@ConversationScoped
class ConversationBean implements Serializable {
	int i;
	
	@Inject
	Conversation c;
	
	public void startConversation() {
		System.out.println(i);
		i=7;
		System.out.println("start conversation bean");
		c.begin();
	}
	
	public void endConversation() {
		i=9;
		System.out.println("end conversation bean");
		System.out.println(i);
		c.end();
	}
}

@ApplicationScoped
class LifeCycleBean {
	public LifeCycleBean() {
		System.out.println("construct");
	}
	@PostConstruct
	private void init() {
		System.out.println("init job ");
	}
	@AroundInvoke
	private Object beforeJob(InvocationContext context) throws Exception {
		System.out.println("before job");
		return context.proceed();
	}
	public void doJob() {
		System.out.println("do job ");
	}
	public void doJob2() {
		System.out.println("do job 2");
	}
	@PreDestroy
	public void preDestroy() {
		System.out.println("pre destroy job ---------------------------------------------------------------------------------------------------------------------");
		Double x=(double) (1/0);
	}
}

class InterceptorBean {
	@AroundConstruct
	private void beforeConstruct(InvocationContext context) throws Exception {
		System.out.println("InterceptorBean before construct");
		context.proceed();
	}
	
	@PostConstruct
	private void postConstruct(InvocationContext context) throws Exception {
		System.out.println("InterceptorBean after construct");
		//context.proceed();
	}
	
	@AroundInvoke
	private Object beforeMethod(InvocationContext context) throws Exception {
		System.out.println("InterceptorBean before method");
		return context.proceed();
	}
	
	@PreDestroy
	private void preDestroy(InvocationContext context) throws Exception {
		System.out.println("InterceptorBean pre destroy");
	}
}

@Interceptors(InterceptorBean.class)
@RequestScoped
class IBean {
	public IBean() {
		System.out.println("ibean construct");
	}
	
	public void doJob() {
		System.out.println("ibean do job ");
	}
	@ExcludeClassInterceptors
	public void doJob2() {
		System.out.println("ibean do job 2");
	}
}

@InterceptorBinding
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD,ElementType.TYPE,ElementType.METHOD})
@interface One{}

@One
@Interceptor
class Interceptor1 {
	@AroundInvoke
	private Object beforeMethod(InvocationContext context) throws Exception {
		System.out.println("pre method 1");
		return context.proceed();
	}
}
class Interceptor2 {
	@AroundInvoke
	private Object beforeMethod(InvocationContext context) throws Exception {
		System.out.println("pre method 2");
		return context.proceed();
	}
}
class Interceptor3 {
	@AroundInvoke
	private Object beforeMethod(InvocationContext context) throws Exception {
		System.out.println("pre method 3");
		return context.proceed();
	}
}
class Interceptor4 {
	@AroundInvoke
	private Object beforeMethod(InvocationContext context) throws Exception {
		System.out.println("pre method 4");
		return context.proceed();
	}
}

@One
@Interceptors ({
	Interceptor2.class,
	Interceptor3.class,
	Interceptor4.class
})
class IBeanChain {
	public void doJob() {
		System.out.println("ibeanchain job");
	}
}

interface Parent {
	void print();
}

class Child implements Parent {
	public void print() {
		System.out.println("child print");
	}
}

@Decorator
class MyDecorator implements Parent {
	
	@Inject
	@Delegate
	private Parent p;
	
	public void print() {
		System.out.println("decorator before");
		p.print();
		System.out.println("decorator after");
	}
}


class Book {
	String name;
	
	public Book(String name) {
		this.name=name;
	}
	
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
	
}


@Qualifier
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD,ElementType.TYPE,ElementType.METHOD,ElementType.PARAMETER})
@interface Add {};

@Qualifier
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD,ElementType.TYPE,ElementType.METHOD,ElementType.PARAMETER})
@interface Remove {};

class BookService {
	@Inject
	@Add
	Event<Book> addEvent;
	
	@Inject
	@Remove
	Event<Book> removeEvent;
	
	public void addBook(Book book) {
		System.out.println(book.getName()+"book was added");
		addEvent.fire(book);
	}
	
	public void removeBook(Book book) {
		System.out.println(book.getName()+"book was removed");
		removeEvent.fire(book);
	}
	
}

@Singleton
class Subscriber {
	List<Book> list=new ArrayList<>();
	
	public void add(@Observes @Add Book book) {
		System.out.println(book.getName()+" added to list");
		list.add(book);
		System.out.println("size list = "+list.size());
	}
	public void delete(@Observes @Remove Book book) {
		System.out.println(book.getName()+" removed from list");
		list.remove(book);
		System.out.println("size list = "+list.size());
	}
}









