package com.example.uaa;

import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.type.TypeReference;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.servlet.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

import static org.springframework.http.HttpMethod.GET;

@SpringBootApplication
@RestController
public class UaaApplication {

	public static void main(String[] args) {
		SpringApplication.run(UaaApplication.class, args);
	}

	@GetMapping("/userinfo")
	Object userinfo(Authentication authentication) {
		return authentication;
	}

	static class CorsFilter implements Filter {
		public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
			HttpServletResponse response = (HttpServletResponse) res;
			response.setHeader("Access-Control-Allow-Origin", "*");
			response.setHeader("Access-Control-Allow-Methods", "*");
			response.setHeader("Access-Control-Max-Age", "3600");
			response.setHeader("Access-Control-Allow-Headers", "authorization");
			chain.doFilter(req, res);
		}

		public void init(FilterConfig filterConfig) {}

		public void destroy() {}
	}

	@Bean
	CorsFilter corsFilter() {
		return new CorsFilter();
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new Pbkdf2PasswordEncoder();
	}

	@Configuration
	static class WebMvcConfig implements WebMvcConfigurer {
		@Override
		public void addViewControllers(ViewControllerRegistry registry) {
			registry.addViewController("/login").setViewName("/login");
		}
	}

	@Configuration
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	@Order(-20)
	static class WebSecurityConfig extends WebSecurityConfigurerAdapter {
		UserDetailsService userDetailsService;

		WebSecurityConfig(UserDetailsService userDetailsService) {
			super();
			this.userDetailsService = userDetailsService;
		}

		// TODO refactor
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.formLogin()
						.loginPage("/login").permitAll()
						.and()
					.requestMatchers()
						.antMatchers("/", "/login", "/logout", "/oauth/authorize", "/oauth/confirm_access")
						.and()
					.authorizeRequests()
						.antMatchers("/login**").permitAll()
						.and()
					.authorizeRequests()
						.antMatchers(HttpMethod.OPTIONS).permitAll()
						.and()
					.userDetailsService(userDetailsService)
						.csrf().ignoringAntMatchers("/oauth/**")
			;
		}

		@Bean
		public AuthenticationManager authenticationManagerBean() throws Exception {
			return super.authenticationManagerBean();
		}
	}

	@Configuration
	@EnableAuthorizationServer
	static class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
		AuthenticationManager authenticationManager;

		public AuthorizationServerConfig(AuthenticationManager authenticationManager) {
			this.authenticationManager = authenticationManager;
		}

		// TODO reactor
		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			clients
					.inMemory()
						.withClient("demo")
						.secret("demo")
						.scopes("read")
						.autoApprove(true)
						.authorizedGrantTypes("implicit")
						.accessTokenValiditySeconds(10)
						.redirectUris(
								"http://localhost:3000/",
								"http://localhost:3000/login",
								"http://localhost:3000/login/oauth2/code/home"
						)
			;
		}

		// TODO need?
		@Override
		public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
			security
					.passwordEncoder(passwordEncoder())
					.checkTokenAccess("isAuthenticated()")
					.tokenKeyAccess("permitAll()");
		}

		// TODO Fix depicted
		private PasswordEncoder passwordEncoder() {
			return new PasswordEncoder() {
				private final PasswordEncoder passwordEncoder = NoOpPasswordEncoder.getInstance();
				@Override
				public boolean matches(CharSequence rawPassword, String encodedPassword) {
					return StringUtils.hasText(encodedPassword) ? passwordEncoder.matches(rawPassword, encodedPassword) : true;
				}
				@Override
				public String encode(CharSequence rawPassword) {
					return passwordEncoder.encode(rawPassword);
				}
			};
		}

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
			tokenEnhancerChain.setTokenEnhancers(Arrays.asList(tokenEnhancer(), jwtAccessTokenConverter()));
			endpoints.tokenEnhancer(tokenEnhancerChain)
					.authenticationManager(authenticationManager);
		}

		@ConfigurationProperties("jwt")
		@Bean
		JwtAccessTokenConverter jwtAccessTokenConverter() {
			return new JwtAccessTokenConverter();
		}

		@Bean
		TokenEnhancer tokenEnhancer() {
			return new CustomTokenEnhancer();
		}
	}

	static class CustomTokenEnhancer implements TokenEnhancer {
		@Override
		public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
			OAuth2User user = (OAuth2User) authentication.getPrincipal();
			Map<String, Object> additionalInfo = new ObjectMapper().convertValue(user, new TypeReference<Map<String, Object>>() {});
			((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);
			return accessToken;
		}
	}

	@Configuration
	@EnableResourceServer
	static class ResourceServerConfig extends ResourceServerConfigurerAdapter {
		@Override
		public void configure(HttpSecurity http) throws Exception {
			http
					.sessionManagement()
						.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
						.and()
					.authorizeRequests()
						.mvcMatchers(GET, "/userinfo").access("#oauth2.hasScope('read')")
			;
		}
	}
}
