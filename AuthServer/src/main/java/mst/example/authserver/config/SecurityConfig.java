package mst.example.authserver.config;

import static java.lang.String.format;


import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import lombok.RequiredArgsConstructor;
import mst.example.authserver.security.jwt.JwtTokenAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import javax.servlet.http.HttpServletResponse;

@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, jsr250Enabled = true, prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

  JwtTokenAuthenticationFilter jwtTokenAuthenticationFilter;

  @Autowired
  public SecurityConfig(JwtTokenAuthenticationFilter jwtTokenAuthenticationFilter) {
    this.jwtTokenAuthenticationFilter = jwtTokenAuthenticationFilter;
  }


/*  @Bean
  public AuthenticationManager authenticationManager(
          AuthenticationConfiguration authenticationConfiguration ) throws Exception {
    PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    return authenticationConfiguration.
            .withUser("admin").password(encoder.encode("admin")).roles("ADMIN", "USER").and()
            .withUser("mosy").password(encoder.encode("1234")).roles("USER").and().and().build();
  }*/


  @Bean
  public AuthenticationManager authenticationManager(
          HttpSecurity http) throws Exception {
    PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
    return http.getSharedObject(AuthenticationManagerBuilder.class)
            .inMemoryAuthentication()
            .withUser("admin").password(encoder.encode("admin")).roles("ADMIN", "USER").and()
            .withUser("mosy").password(encoder.encode("1234")).roles("USER")
            .and().and().parentAuthenticationManager(null).build();
  }




  /*
  protected void getauth(AuthenticationManagerBuilder auth) throws Exception {
    PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
    auth.inMemoryAuthentication()
            .withUser("admin").password(encoder.encode("admin")).roles("ADMIN", "USER").and()
            .withUser("mosy").password(encoder.encode("1234")).roles("USER");
  }


  @Bean
  public AuthenticationManager authenticationManager(
      HttpSecurity http, PasswordEncoder encoder) throws Exception {
    return http.getSharedObject(AuthenticationManagerBuilder.class)
            .inMemoryAuthentication()
            .withUser("admin").password(encoder.encode("admin")).roles("ADMIN", "USER").and()
            .withUser("mosy").password(encoder.encode("1234")).roles("USER").and().and().build();
  }
*/

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    // Enable CORS and disable CSRF
    http.cors().and().csrf().disable();

    // Set session management to stateless
    http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    // Set unauthorized requests exception handler
    http.exceptionHandling(
        (exceptions) ->
            exceptions

                .authenticationEntryPoint((req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED))
                .accessDeniedHandler((req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_FORBIDDEN)));

    // Set permissions on endpoints
    http.authorizeRequests()
        // Swagger endpoints must be publicly accessible
        .antMatchers("/auth/**" )
        .permitAll()
        // Our private endpoints
        .anyRequest()
        .authenticated();
        // Set up oauth2 resource server


    http.addFilterBefore(jwtTokenAuthenticationFilter,
            UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }


  // Used by spring security if CORS is enabled.
  @Bean
  public CorsFilter corsFilter() {
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowCredentials(true);
    config.addAllowedOrigin("*");
    config.addAllowedHeader("*");
    config.addAllowedMethod("*");
    source.registerCorsConfiguration("/**", config);
    return new CorsFilter(source);
  }


}
