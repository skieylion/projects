package mytest.config;

import java.util.Properties;
import javax.annotation.Resource;
import javax.sql.DataSource;

import org.hibernate.Session;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import com.mysql.cj.xdevapi.SessionFactory;

import org.springframework.core.env.Environment;

@Configuration
@EnableTransactionManagement
@EnableWebMvc
@ComponentScan("mytest")
@PropertySource("classpath:configData.properties")
@EnableJpaRepositories("mytest.repository")
public class DataConfig {
	
	private static final String DRIVER="db.driver";
	private static final String PASSWORD="";
	private static final String URL="db.url";
	private static final String USER_NAME="db.username";
	private static final String DIALECT="db.hibernate.dialect";
	private static final String SHOW_SQL="db.hibernate.show_sql";
	private static final String PACKEAGE_SCAN="db.entitymanager.packages.to.scan";
	private static final String HBM2DDL="db.hibernate.hbm2ddl.auto";
	
	@Resource
	private Environment env;
	
	@Bean
	public DataSource dataSource() {
		DriverManagerDataSource dataSource=new DriverManagerDataSource();
		dataSource.setDriverClassName(env.getRequiredProperty(DRIVER));
		dataSource.setUrl(env.getRequiredProperty(URL));
		dataSource.setUsername(env.getRequiredProperty(USER_NAME));
		dataSource.setPassword(PASSWORD);
		return dataSource;
	}
	
	@Bean
	public LocalContainerEntityManagerFactoryBean entityManagerFactory() {
		LocalContainerEntityManagerFactoryBean entityManagerFactoryBean=new LocalContainerEntityManagerFactoryBean();
		entityManagerFactoryBean.setDataSource(dataSource());
		HibernateJpaVendorAdapter vendor =new HibernateJpaVendorAdapter();
		entityManagerFactoryBean.setJpaVendorAdapter(vendor);
		entityManagerFactoryBean.setPackagesToScan(env.getRequiredProperty(PACKEAGE_SCAN));
		entityManagerFactoryBean.setJpaProperties(getHibernateProperties());
		
		return entityManagerFactoryBean;
	}
	
	@Bean
	public JpaTransactionManager transactionManager() {
		JpaTransactionManager transactionManager = new JpaTransactionManager();
		transactionManager.setEntityManagerFactory(entityManagerFactory().getObject());
		return transactionManager;
	}
	
	private Properties getHibernateProperties() {
        Properties properties = new Properties();
        properties.put(DIALECT, env.getRequiredProperty(DIALECT));
        properties.put(SHOW_SQL,env.getRequiredProperty(SHOW_SQL));
        properties.put(HBM2DDL,env.getRequiredProperty(HBM2DDL));
        
        return properties;
    }
	
	
}
