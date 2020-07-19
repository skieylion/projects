package mytest.entity;

import java.sql.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.transaction.Transactional;

@Entity
@Table(name="events")
public class Event {
	
	@Id
	@Column(name="Id",nullable=false)
	private long id;
	
	@Column(name="Name")
	private String name;
	
	@Column(name="Description")
	private String description;
	
	@Column(name="DueDate")
	private Date dueDate;
	
	

	@Column(name="StartDate")
	private Date startDate;
	
	
	public Event() {
		
	}
	
	public Event(String name) {
		this.name=name;
	}
	
	@Transactional
	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
	}
	
	@Transactional
	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
	
	@Transactional
	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}
	
	@Transactional
	public Date getDueDate() {
		return dueDate;
	}

	public void setDueDate(Date dueDate) {
		this.dueDate = dueDate;
	}
	
	@Transactional
	public Date getStartDate() {
		return startDate;
	}

	public void setStartDate(Date startDate) {
		this.startDate = startDate;
	}
	
}
