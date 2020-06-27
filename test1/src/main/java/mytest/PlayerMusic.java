package mytest;

public class PlayerMusic {
	private Music music;
	public PlayerMusic(Music music) {
		this.music=music;
	}
	public void playMusic() {
		System.out.println(music.getSong());
	}
}
