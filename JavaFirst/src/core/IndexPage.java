package core;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.net.HttpURLConnection;
import java.io.BufferedReader;
import java.net.URL;
import java.io.InputStreamReader;

/**
 * Servlet implementation class IndexPage
 */
@WebServlet("/IndexPage")
public class IndexPage extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public IndexPage() {
        super();
        // TODO Auto-generated constructor stub
    }
    
    
	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		String query="http://www.cbr.ru/scripts/XML_daily.asp";
		HttpURLConnection connect=null;
		try {
			connect = (HttpURLConnection) new URL(query).openConnection();
			connect.setRequestMethod("GET");
			connect.connect();
			
			StringBuilder sb=new StringBuilder();
			
			if(HttpURLConnection.HTTP_OK==connect.getResponseCode()) {
				BufferedReader br=new BufferedReader(new InputStreamReader(connect.getInputStream()));
				String line;
				while((line=br.readLine())!=null) {
					sb.append(line);
				}
				
				System.out.println(sb);
			}
			
		} catch (Exception e) {
			System.out.print(e);
		} finally {
			if(connect!=null) {
				connect.disconnect();
			}
		}
		
		
		response.getWriter().append("Served at: ").append(request.getContextPath());
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		doGet(request, response);
	}

}
