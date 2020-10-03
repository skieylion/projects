package test;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import javax.validation.Constraint;
import javax.validation.Payload;

@Constraint(validatedBy= {CheckChronLogic.class})
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD,ElementType.TYPE,ElementType.METHOD})
public @interface ChronDates {
	String message() default "Email address doesn't took good";
	Class<?>[] groups() default{};
	Class<? extends Payload>[] payload() default{};
}
