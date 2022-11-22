package com.security.testing.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;

import static com.security.testing.security.ApplicationUserRole.*;
import static com.security.testing.security.ApplicationUserPermission.*;

@Configuration
@EnableWebSecurity
public class applicationSecurityConfig{
	
	// it helps to encode the password with BCRYPT,  without encryption we can't login to basic AUTH
	private final PasswordEncoder passwordEncoder;
	
	
	@Autowired
	 public applicationSecurityConfig(PasswordEncoder passwordEncoder) {
		super();
		this.passwordEncoder = passwordEncoder;
	}
	// this is used to implement the basic AUTH security
		@Bean
	    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
	        http
	        .csrf().disable()
	        .authorizeRequests()
	        .antMatchers("index","/css/**","/js/**").permitAll()
	        .antMatchers("/api/**").hasRole(STUDENT.name())
	        .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
	        .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
	        .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
	        .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())
	        .anyRequest()
	        .authenticated()
	        .and()
	        .httpBasic();
	        return http.build();
	    }
	 
	
	 @Bean 
	 public UserDetailsService userDetailsService() {
		 
		 // All users has their own roles and permissions
		 
		 // user 1: it has a role of student
		 UserDetails saadUllah = User.builder()
		 .username("Saad")
		 .password(passwordEncoder.encode("loser"))
		 .authorities(STUDENT.getGrantedAuthorities())
//		 .roles(STUDENT.name())
		 .build();
		 
		 // user 2: it has a role of admin
		 UserDetails abid = User.builder()
				 .username("abid")
				 .password(passwordEncoder.encode("password"))
//				 .roles(ADMIN.name())
				 .authorities(ADMIN.getGrantedAuthorities())
				 .build();
		 
		// user 3: it has a role of admin_Trainee
				 UserDetails talha = User.builder()
						 .username("talha")
						 .password(passwordEncoder.encode("password123"))
//						 .roles(ADMINTRAINEE.name())
						 .authorities(ADMINTRAINEE.getGrantedAuthorities())
						 .build();
		 
				 // In memory user detail manager carries the list of users or a single user
				 
				 // now the question is we have UserDetailService return type
				 // but we are returning InMemoryUserDetailsManager
				 
				 //The answer is: class InMemoryUserDetailsManager implements an interface called  UserDetailsManager
				 // and  UserDetailsManager interface extends from UserDetailsService
				 // So we are returning the same type;
				 
		 return new InMemoryUserDetailsManager(
				 saadUllah,
				 abid,
				 talha
				 );
	 }
}
