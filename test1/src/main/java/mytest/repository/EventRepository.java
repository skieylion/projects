package mytest.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import mytest.entity.Event;

@Repository
public interface EventRepository extends JpaRepository<Event,Long> {
	
}
