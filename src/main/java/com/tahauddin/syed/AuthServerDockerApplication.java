package com.tahauddin.syed;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class AuthServerDockerApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthServerDockerApplication.class, args);
	}

}
