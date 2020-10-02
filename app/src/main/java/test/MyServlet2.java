package test;

import java.io.IOException;
import java.util.Set;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.net.URL;
import test.CheckSite;

import javax.annotation.Resource;
import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;
import javax.validation.constraints.Min;
import javax.validation.constraints.Pattern;
import javax.inject.Qualifier;

import java.io.IOException;
import java.io.Serializable;
import java.lang.annotation.Retention;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.decorator.Decorator;
import javax.decorator.Delegate;
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
import javax.validation.constraints.Future;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Past;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

/**
 * Servlet implementation class MyServlet2
 */
@WebServlet("/MyServlet2")
public class MyServlet2 extends HttpServlet {
	private static final long serialVersionUID = 1L;
    
	@Inject
	MyPerson person;
	
	@Inject
	Validator vl;
	
    /**
     * @see HttpServlet#HttpServlet()
     */
    public MyServlet2() {
        super();
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		
		// TODO Auto-generated method stub
		person.age=14;
		person.name="фыапывпр56н5г47керн";
		
		Set<ConstraintViolation<MyPerson>> validate=vl.validate(person);
		
		if(validate.size()>0) {
			System.out.println("ERROR VALIDATION");
		}
		
		for(ConstraintViolation<MyPerson> violation:validate) {
			System.out.println(violation.getMessage());
			System.out.println(violation.getInvalidValue());
		}
		
		Set<ConstraintViolation<MyPerson>> name=vl.validateProperty(person,"name");
		if(name.size()>0) {
			System.out.println("ERROR VALIDATION NAME"); 
			
		}
		System.out.println("---------------------------------------------");
		Set<ConstraintViolation<MyPerson2>> email=vl.validateValue(MyPerson2.class, "email","ivanov@gmail.ru");
		System.out.println("****************************");
		for(ConstraintViolation<MyPerson2> violation:email) {
			System.out.println(violation.getMessage());
			System.out.println(violation.getInvalidValue());
		}
		System.out.println("****************************");
		
		Set<ConstraintViolation<MyPerson2>> site=vl.validateValue(MyPerson2.class, "site","muasd.ru");
		System.out.println("++++++++++++++++++++++++++++++++++++++");
		for(ConstraintViolation<MyPerson2> violation:site) {
			System.out.println(violation.getMessage());
			System.out.println(violation.getInvalidValue());
		}
		System.out.println("++++++++++++++++++++++++++++++++++++++");
		
		response.getWriter().append("Served at: ").append(request.getContextPath());
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		doGet(request, response);
	}

}

class MyPerson{
	@Pattern(regexp="[A-Z][a-z]*")
	String name;
	@Min(18)
	int age;
	
}

class MyPerson2 {
	@CheckEmail
	public String email;
	
	@CheckSite(host="mysite.com")
	public String site;
}

@Qualifier
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD})
@interface ValitationInit {};

class MyValidator {
	@Produces
	public Validator getValidator() {
		ValidatorFactory vf=Validation.buildDefaultValidatorFactory();
		Validator vl=vf.getValidator();
		return vl;
	}
}






