package com.futbolix.customers;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class CustomersApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(CustomersApiApplication.class, args);
    }
}
