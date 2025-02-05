package com.oauth2starter.springsecurityoauth2starter;

import io.github.cdimascio.dotenv.Dotenv;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@Slf4j
public class Springsecurityoauth2starterApplication {
	static {
		Dotenv dotenv = Dotenv.configure().directory("src/main/resources").load();
		dotenv.entries().forEach(entry -> {
			System.setProperty(entry.getKey(), entry.getValue());
		});
	}
	public static void main(String[] args) {
		SpringApplication.run(Springsecurityoauth2starterApplication.class, args);
	}

}
