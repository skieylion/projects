package mytest;

import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Scope;
import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;

@Component("musicPlayer")
@Scope("singleton")
public class PlayerMusic {
	private Music music;
	@Value("${musicPlayer.name}")
	private String name;
	@Value("${musicPlayer.volume}")
	private Integer volume;
	
	
	public PlayerMusic(Music music) {
		this.music=music;
	}
	public PlayerMusic() {
		
	}
	public void playMusic() {
		System.out.println(music.getSong());
	}
	@Autowired
	@Qualifier("rockMusic")
	public void setMusic(Music music) {
		this.music=music;
	}
	public void setName(String name) {
		this.name=name;
	}
	public String getName() {
		return this.name;
	}
	public void setVolume(Integer volume) {
		this.volume=volume;
	}
	public Integer getVolume() {
		return this.volume;
	}
	@PostConstruct
	public void doMyInit() {
		System.out.println("init");
	}
	@PreDestroy
	public void doMyDestroy() {
		System.out.println("destroy");
	}
}
