package telran.java47.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class AuthorizationConfiguration {

	@Bean
	public SecurityFilterChain configure(HttpSecurity http) throws Exception {
		http.httpBasic(withDefaults());
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		http.authorizeRequests(authorize -> authorize.mvcMatchers("/account/register", "/forum/posts/**").permitAll()

				.mvcMatchers("/account/user/{login}/role/{role}")
				.access("@customSecurity.passwordNotExpireCheck and hasRole('ADMINISTRATOR')")

				.mvcMatchers(HttpMethod.PUT, "/account/user/{login}")
				.access("#login == authentication.name and @customSecurity.passwordNotExpireCheck")

				.mvcMatchers(HttpMethod.DELETE, "/account/user/{login}")
				.access("(#login == authentication.name or hasRole('ADMINISTRATOR')) and @customSecurity.passwordNotExpireCheck")

				.mvcMatchers(HttpMethod.POST, "/forum/post/{author}")
				.access("#author == authentication.name and @customSecurity.passwordNotExpireCheck")

				.mvcMatchers(HttpMethod.PUT, "/forum/post/{id}/comment/{author}")
				.access("#author == authentication.name and @customSecurity.passwordNotExpireCheck")

				.mvcMatchers(HttpMethod.PUT, "/forum/post/{id}")
				.access("@customSecurity.checkPostAuthor(#id, authentication.name) and @customSecurity.passwordNotExpireCheck")

				.mvcMatchers(HttpMethod.DELETE, "/forum/post/{id}")
				.access("(@customSecurity.checkPostAuthor(#id, authentication.name) or (hasRole('MODERATOR'))) and @customSecurity.passwordNotExpireCheck")

				.anyRequest().authenticated());

		return http.build();
	}
}
