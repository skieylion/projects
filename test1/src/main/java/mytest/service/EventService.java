package mytest.service;

import java.util.List;

import org.springframework.stereotype.Service;

import mytest.entity.Event;

public interface EventService {
	Event add(Event p);
	void remove(long id);
	Event getById(long id);
	Event edit(Event p);
	List<Event> getAll();
}
