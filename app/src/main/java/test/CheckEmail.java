package test;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import javax.inject.Qualifier;
import javax.validation.Constraint;
import javax.validation.Payload;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

@NotNull
@Size(min=7)
@Pattern(regexp="[A-Za-z0-9]*@[A-Za-z0-9]*\\.com")
@Constraint(validatedBy= {})
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD,ElementType.TYPE,ElementType.METHOD})
@interface CheckEmail {
	String message() default "Email address doesn't took good";
	Class<?>[] groups() default{};
	Class<? extends Payload>[] payload() default{};
}
