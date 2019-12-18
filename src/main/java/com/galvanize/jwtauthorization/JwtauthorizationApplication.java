package com.galvanize.jwtauthorization;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;

@EnableZuulProxy
@SpringBootApplication
public class JwtauthorizationApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtauthorizationApplication.class, args);
    }

}

