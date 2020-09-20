import javax.inject.Inject;

public class MDB2 {
	@Inject
	@AHandler2
	IHandler ih;
	
	public void onMessage(String m) {
		ih.Call(m);
	}
}
