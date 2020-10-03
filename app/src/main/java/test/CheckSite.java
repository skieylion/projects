package test;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import javax.validation.Constraint;
import javax.validation.Payload;
import test.CheckSiteLogic;

@Constraint(validatedBy= {CheckSiteLogic.class})
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD,ElementType.TYPE,ElementType.METHOD})
public @interface CheckSite {
	String message() default "${javax.validation.constraints.url.port.message} !!!!!!!";
	Class<?>[] groups() default{};
	Class<? extends Payload>[] payload() default{};
	int port() default -1;
	String host() default "";
	String protocol() default "";
}
