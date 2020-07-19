package mytest.service.impl;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.websocket.Session;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;

import mytest.entity.Event;
import mytest.repository.EventRepository;
import mytest.service.EventService;

@Service
public class EventServiceImpl implements EventService {
	
	@Autowired
	private EventRepository eventRepository;
	
	
	
	public Event add(Event e) {
		Event saveEvent=eventRepository.saveAndFlush(e);
		return saveEvent;
	}

	public void remove(long id) {
		eventRepository.deleteById(id);
	}
	
	public Event getById(long id) {
		return eventRepository.getOne(id);
	}

	public Event edit(Event p) {
		return eventRepository.saveAndFlush(p);
	}

	public List<Event> getAll() {
		return eventRepository.findAll();
	}
	
}
