package com.example.spriingSecurity1;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
@EnableWebSecurity
public class SpriingSecurity1Application {

	public static void main(String[] args) {
		SpringApplication.run(SpriingSecurity1Application.class, args);
	}

}
