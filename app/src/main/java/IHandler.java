
public interface IHandler {
	public void Execute(String d);
	public default void Call(String message) {
		System.out.println("Преобразуем объект: "+message);
		Execute(message);
	}
}
