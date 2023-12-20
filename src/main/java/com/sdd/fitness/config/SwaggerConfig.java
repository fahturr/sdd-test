package com.sdd.fitness.config;


import com.sdd.fitness.constant.Scheme;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    @Value("${com.sdd.fitness.app-version}")
    private String appVersion;

    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
                .components(components())
                .info(info());
    }

    private Info info() {
        return new Info()
                .title("Fitness Membership API")
                .version(appVersion)
                .license(new License().name("Apache 2.0").url("http://springdoc.org"))
                .description("com.sdd.fitness - API Swagger documentation");
    }

    private Components components() {
        return new Components()
                .addSecuritySchemes(
                        Scheme.AUTHORIZATION,
                        new SecurityScheme()
                                .name(Scheme.AUTHORIZATION)
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("Bearer")
                                .bearerFormat("JWT")
                );
    }

}
