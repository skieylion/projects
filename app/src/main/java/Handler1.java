import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import javax.inject.Qualifier;

@Qualifier
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD,ElementType.TYPE,ElementType.METHOD})
@interface AHandler1 {};

@AHandler1
public class Handler1 implements IHandler {
	public void Execute(String d) {
		System.out.println("В Handler1 пришел: "+d);
	}
}
