package com.tintin.blog;

import jakarta.annotation.PostConstruct;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.convert.Jsr310Converters;

import java.util.TimeZone;

@SpringBootApplication
@EntityScan(basePackageClasses = {
		BlogApplication.class,
		Jsr310Converters.class
})
public class BlogApplication {

	@PostConstruct
	void init() {
		TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
	}

	public static void main(String[] args) {
		SpringApplication.run(BlogApplication.class, args);
	}

//	@Bean
//	CommandLineRunner run(UserService userService) {
//		return args -> {
//			userService.saveRole(new Role(RoleName.ROLE_ADMIN));
//			userService.saveRole(new Role(RoleName.ROLE_USER));
//		};
//	}

}
