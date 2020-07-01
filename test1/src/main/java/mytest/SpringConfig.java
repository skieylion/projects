package mytest;

import org.springframework.context.annotation.*;


@Configuration
@ComponentScan("mytest")
@PropertySource("classpath:musicPlayer.properties")
public class SpringConfig {

}
