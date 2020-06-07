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
import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import javax.xml.bind.*;

import tdata.*;

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
				
				String str=sb.toString();
				Charset utf8=Charset.forName("Windows-1251");
				byte[] bytes=str.getBytes(utf8);
				ByteArrayInputStream byteArray=new ByteArrayInputStream(bytes);
				
				JAXBContext jc=JAXBContext.newInstance(ValCurs.class);
				Unmarshaller ums=jc.createUnmarshaller();
				ValCurs vc=(ValCurs)ums.unmarshal(byteArray);
				
				//response.setContentType("html/text");
				response.setCharacterEncoding("Windows-1251");
				
				response.getWriter().append("<table border=1>");
				
					response.getWriter().append("<thead>");
						response.getWriter().append("<th>");
							response.getWriter().append("Букв. код");
						response.getWriter().append("</th>");
						response.getWriter().append("<th>");
							response.getWriter().append("Единиц");
						response.getWriter().append("</th>");
						response.getWriter().append("<th>");
							response.getWriter().append("Валюта");
						response.getWriter().append("</th>");
						response.getWriter().append("<th>");
							response.getWriter().append("Курс");
						response.getWriter().append("</th>");
					response.getWriter().append("</thead>");
					
					response.getWriter().append("<tbody>");
					
						for(int i=0;i<vc.getValute().size();i++) {
							ValCurs.Valute v=vc.getValute().get(i);
							response.getWriter().append("<tr>");
								response.getWriter().append("<td>");
									response.getWriter().append(v.getCharCode());
								response.getWriter().append("</td>");
								response.getWriter().append("<td>");
									response.getWriter().append(String.valueOf(v.getNominal()));
								response.getWriter().append("</td>");
								response.getWriter().append("<td>");
									response.getWriter().append(v.getName());
								response.getWriter().append("</td>");
								response.getWriter().append("<td>");
									response.getWriter().append(v.getValue());
								response.getWriter().append("</td>");
							response.getWriter().append("</tr>");
						}
						
					response.getWriter().append("</tbody>");
					
				response.getWriter().append("</table>");
				
				
				
			}
			
		} catch (Exception e) {
			System.out.print(e);
		} finally {
			if(connect!=null) {
				connect.disconnect();
			}
		}
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		doGet(request, response);
	}

}
