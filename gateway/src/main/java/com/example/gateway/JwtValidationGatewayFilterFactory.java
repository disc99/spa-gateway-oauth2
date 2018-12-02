package com.example.gateway;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;

import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JwtValidationGatewayFilterFactory extends AbstractGatewayFilterFactory<JwtValidationGatewayFilterFactory.Config> {
    Pattern pattern = Pattern.compile("Bearer (.*)");

	public JwtValidationGatewayFilterFactory() {
		super(Config.class);
	}

	@Override
	public GatewayFilter apply(Config config) {
		return (exchange, chain) -> {
			try {
				verify(exchange, config);
				return chain.filter(exchange);
			} catch (RuntimeException e) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
				return exchange.getResponse().setComplete();
			}
		};
	}

	private void verify(ServerWebExchange exchange, Config config) {
		String authorization = exchange.getRequest().getHeaders().getFirst("Authorization");
		Matcher matcher = pattern.matcher(authorization);
		if (!matcher.find()) {
		    throw new IllegalArgumentException("Not exist Access Token");
		}

        Jwts.parser()
				.setSigningKeyResolver(new SigningKeyResolverAdapter() {
					@Override
					public Key resolveSigningKey(JwsHeader header, Claims claims) {
						return config.publicKey;
					}
				})
				.parseClaimsJws(matcher.group(1)).getBody();
    }

	public static class Config {
		PublicKey publicKey;
		public Config() {
            TokenKey tokenKey = new RestTemplate().getForObject("http://localhost:9999/uaa/oauth/token_key", TokenKey.class);
            String pubKeyPEM = tokenKey.value.replaceAll("(-+BEGIN PUBLIC KEY-+\\r?\\n|-+END PUBLIC KEY-+\\r?\\n?)", "");
            this.publicKey = rsa(pubKeyPEM);
		}

		private PublicKey rsa(String pubKeyPEM) {
			try {
				return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.decode(pubKeyPEM)));
			} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
				throw new IllegalArgumentException(e);
			}
		}
	}

	static class TokenKey {
		String alg;
		String value;
        public void setAlg(String alg) {
            this.alg = alg;
        }
        public void setValue(String value) {
            this.value = value;
        }
    }
}
