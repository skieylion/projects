package test;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class CheckChronLogic implements ConstraintValidator<ChronDates,MyValidate> {

	@Override
	public void initialize(ChronDates constraintAnnotation) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public boolean isValid(MyValidate value, ConstraintValidatorContext context) {
		// TODO Auto-generated method stub
		return value.bithDate.isBefore(value.deathDate);
	}

}
