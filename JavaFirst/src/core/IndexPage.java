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
import java.io.FileReader;
import java.io.FileWriter;
import java.util.Scanner;
import java.util.Date;

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
		String pathCash="D:/work/projects/JavaFirst/cash.txt";
		HttpURLConnection connect=null;
		FileReader fr=null;
		StringBuilder xmlData=null;
		boolean isCash=false;
		
		try {
			fr=new FileReader(pathCash);
			Scanner scan=new Scanner(fr);
			Long dateLast=-1L;
			
			if(scan.hasNextLine()) {
				String buff=scan.nextLine();
				dateLast=Long.parseLong(buff);
				Date d=new Date();
				d.setHours(0);
				d.setMinutes(0);
				d.setSeconds(1);
				long current=d.getTime();
				
				if(dateLast>current&&dateLast<current+24*60*60*1000) {
					isCash=true;
					xmlData=new StringBuilder();
					while(scan.hasNextLine()) {
						xmlData.append(scan.nextLine());
					}
					
				}
				
			}
			
		} catch(Exception e) {
			System.out.print(e);
		} finally {
			if(fr!=null) {
				fr.close();
			}
		}
		
		try {
			
			if(xmlData==null) {
				connect = (HttpURLConnection) new URL(query).openConnection();
				connect.setRequestMethod("GET");
				connect.connect();
				
				xmlData=new StringBuilder();
				
				if(HttpURLConnection.HTTP_OK==connect.getResponseCode()) {
					BufferedReader br=new BufferedReader(new InputStreamReader(connect.getInputStream()));
					String line;
					while((line=br.readLine())!=null) {
						xmlData.append(line);
					}
					
				}
			}
			
			
			String str=xmlData.toString();
			Charset utf8=Charset.forName("Windows-1251");
			byte[] bytes=str.getBytes(utf8);
			ByteArrayInputStream byteArray=new ByteArrayInputStream(bytes);
			
			if(isCash==false) {
				FileWriter fw=null;
				try {
					fw=new FileWriter(pathCash);
					Date d=new Date();
					long dateCash=d.getTime();
					fw.write(String.valueOf(dateCash));
					fw.write("\n");
					fw.write(str);
				} catch(Exception e) {
					System.out.println(e);
				} finally {
					if(fw!=null) {
						fw.close();
					}
				}
			}
			
			
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
