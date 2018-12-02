package com.example.uaa;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class OAuth2UserDetailsService implements UserDetailsService {
    JdbcTemplate jdbcTemplate;

    public OAuth2UserDetailsService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String sql = String.format("SELECT * FROM users WHERE name = '%s'", username);
        List<OAuth2User> users = jdbcTemplate.query(sql, (rs, rowNum) -> new OAuth2User(
                rs.getString("name"),
                rs.getString("password"),
                rs.getString("email")
        ));

        if (users.size() == 1) {
            return users.get(0);
        }

        throw new UsernameNotFoundException("user not found: name = " + username);
    }
}
