package test;
import java.net.URL;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
public class CheckSiteLogic implements ConstraintValidator<CheckSite,String> {
	public int port;public String host;public String protocol;
	@Override
	public void initialize(CheckSite constraintAnnotation) {
		// TODO Auto-generated method stub
		this.protocol=constraintAnnotation.protocol();
		this.host=constraintAnnotation.host();
		this.port = constraintAnnotation.port();
	}
	@Override
	public boolean isValid(String value, ConstraintValidatorContext context) {
		// TODO Auto-generated method stub
		if(value==null || value.equals("")) {return true;}
		URL url;
		try {url=new URL(value);} catch(Exception e) {return false;}
		if(protocol!=null&&protocol.length()>0&&!protocol.equals(url.getProtocol())) {
			context.disableDefaultConstraintViolation();
			context.buildConstraintViolationWithTemplate("protocol invalid").addConstraintViolation();
			return false;
		}
		if(host!=null&&host.length()>0&&!host.equals(url.getHost())) {
			context.disableDefaultConstraintViolation();
			context.buildConstraintViolationWithTemplate("host invalid").addConstraintViolation();	
			return false;
		}
		if(port!=-1&&port!=url.getPort()) {
			//context.disableDefaultConstraintViolation();
			//context.buildConstraintViolationWithTemplate("port invalid").addConstraintViolation();		
			return false;
		}
		return true;
	}
}