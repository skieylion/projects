import javax.inject.Inject;

public class MDB1 {
	@Inject
	@AHandler1
	IHandler ih;
	
	public void onMessage(String m) {
		ih.Call(m);
	}
}
