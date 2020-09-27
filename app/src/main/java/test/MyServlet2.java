package test;

import java.io.IOException;
import java.util.Set;

import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;
import javax.validation.constraints.Min;
import javax.validation.constraints.Pattern;

/**
 * Servlet implementation class MyServlet2
 */
@WebServlet("/MyServlet2")
public class MyServlet2 extends HttpServlet {
	private static final long serialVersionUID = 1L;
    
	@Inject
	MyPerson person;
	
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
		
		ValidatorFactory vf=Validation.buildDefaultValidatorFactory();
		Validator vl=vf.getValidator();
		
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
