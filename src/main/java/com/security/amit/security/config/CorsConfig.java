package com.security.amit.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableWebMvc
public class CorsConfig implements WebMvcConfigurer {

    private static final String[] CORS_ALLOW_URLS = {"http://localhost:3000"};

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins(CORS_ALLOW_URLS)
                .allowedMethods("GET", "POST", "PATCH")
                .allowedHeaders("*")
                .allowCredentials(true).maxAge(3600);
    }
}
