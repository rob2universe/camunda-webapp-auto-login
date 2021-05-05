package org.camunda.example;

import org.camunda.example.filter.AutoLoginAuthenticationFilter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class Application {

    public static void main(String... args) {
        SpringApplication.run(Application.class, args);
    }

    @Bean
    public FilterRegistrationBean httpBasicAuthFilter() {

        FilterRegistrationBean registration = new FilterRegistrationBean(new AutoLoginAuthenticationFilter());
        registration.addUrlPatterns("/camunda/app/*");
        registration.setName("camunda-auto-login");
        registration.setOrder(1);
        return registration;
    }
}