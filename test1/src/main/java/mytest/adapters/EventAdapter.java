package mytest.adapters;

import java.sql.Date;

public class EventAdapter {
	private String typeEvent;
	private String nameTask;
	private String descriptionTask;
	private Date dueDateTask;
	
	public Date getDueDateTask() {
		return dueDateTask;
	}
	public void setDueDateTask(Date dueDateTask) {
		this.dueDateTask = dueDateTask;
	}
	public String getTypeEvent() {
		return typeEvent;
	}
	public void setTypeEvent(String typeEvent) {
		this.typeEvent = typeEvent;
	}
	public String getNameTask() {
		return nameTask;
	}
	public void setNameTask(String nameTask) {
		this.nameTask = nameTask;
	}
	public String getDescriptionTask() {
		return descriptionTask;
	}
	public void setDescriptionTask(String descriptionTask) {
		this.descriptionTask = descriptionTask;
	}
	
}
