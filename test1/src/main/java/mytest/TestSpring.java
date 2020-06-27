package mytest;

import org.springframework.context.support.ClassPathXmlApplicationContext;

public class TestSpring {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		ClassPathXmlApplicationContext context = new ClassPathXmlApplicationContext(
				"applicationContext.xml"
		);
		//Music music=context.getBean("musicBean",Music.class);
		
		PlayerMusic musicPlayer=context.getBean("musicPlayer",PlayerMusic.class); //new PlayerMusic(music);
		musicPlayer.playMusic();
		
		context.close();
	}

}
