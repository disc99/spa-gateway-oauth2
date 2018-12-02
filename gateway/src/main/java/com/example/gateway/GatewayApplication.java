package com.example.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.util.pattern.PathPatternParser;



@SpringBootApplication
public class GatewayApplication {

	@Bean
	public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
		return builder.routes()
				.route("route_1", r -> r
						.host("localhost:8080")
						.filters(f -> f
								.filter(new JwtValidationGatewayFilterFactory().apply(new JwtValidationGatewayFilterFactory.Config()))
								.setResponseHeader("Access-Control-Allow-Origin", "*")
						)
						.uri("http://faker.hook.io")
				).build();
	}

	@Bean
	public CorsWebFilter corsFilter() {
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource(new PathPatternParser());
		CorsConfiguration config = new CorsConfiguration();
		config.addAllowedOrigin("*");
		config.addAllowedMethod("*");
		config.addAllowedHeader("*");
		source.registerCorsConfiguration("/**", config);
		return new CorsWebFilter(source);
	}

	public static void main(String[] args) {
		SpringApplication.run(GatewayApplication.class, args);
	}
}

