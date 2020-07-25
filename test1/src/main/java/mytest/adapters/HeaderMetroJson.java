package mytest.adapters;

import java.util.List;

public class HeaderMetroJson {
	private List<HeaderMetro> header;
	private List<List<String>> data;
	
	public List<HeaderMetro> getHeader() {
		return header;
	}
	public void setHeader(List<HeaderMetro> header) {
		this.header = header;
	}
	public List<List<String>> getData() {
		return data;
	}
	public void setData(List<List<String>> data) {
		this.data = data;
	}
}
