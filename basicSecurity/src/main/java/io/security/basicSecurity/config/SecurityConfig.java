package io.security.basicSecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
public class SecurityConfig {

//    @Autowired
//    UserDetailsService userDetailsService;

    @Bean
    public InMemoryUserDetailsManager inMemoryUser() {
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        UserDetails admin = User.withUsername("admin").password("{noop}1111").roles("ADMIN").build();
        UserDetails sys = User.withUsername("sys").password("{noop}1111").roles("SYS").build();

        return new InMemoryUserDetailsManager(user, admin, sys);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .userDetailsService(inMemoryUser());

        http
                .authorizeRequests()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated()
                .and()
                .formLogin();
//                .loginPage("/loginPage")
//                .defaultSuccessUrl("/")
//                .failureUrl("/login")
//                .usernameParameter("userId")
//                .passwordParameter("passwd")
//                .loginProcessingUrl("/login")
//                .successHandler(authenticationSuccessHandler())
//                .failureHandler(authenticationFailureHandler())
//                .permitAll();

//        http
//                .rememberMe()
//                .rememberMeParameter("remember")
//                .tokenValiditySeconds(3600)
//                .userDetailsService(userDetailsService);
//
//        http
//                .logout()
//                .logoutUrl("/logout")
//                .logoutSuccessUrl("/login")
//                .addLogoutHandler(logoutHandler())
//                .logoutSuccessHandler(logoutSuccessHandler())
//                .deleteCookies("remember-me");

//        http
//                .sessionManagement()
//                .sessionFixation().changeSessionId()
//                .maximumSessions(1)
//                .maxSessionsPreventsLogin(false);

        return http.build();
    }

//    @Bean
//    public AuthenticationSuccessHandler authenticationSuccessHandler() {
//        return new AuthenticationSuccessHandler() {
//            @Override
//            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                System.out.println("authentication : " + authentication.getName());
//                response.sendRedirect("/");
//            }
//        };
//    }
//    @Bean
//    public AuthenticationFailureHandler authenticationFailureHandler() {
//        return new AuthenticationFailureHandler() {
//            @Override
//            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                System.out.println("exception : " + exception.getMessage());
//                response.sendRedirect("/login");
//            }
//        };
//    }
//
//    @Bean
//    public LogoutHandler logoutHandler() {
//        return new LogoutHandler() {
//            @Override
//            public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//                HttpSession httpSession = request.getSession();
//                httpSession.invalidate();
//            }
//        };
//    }
//
//    @Bean
//    public LogoutSuccessHandler logoutSuccessHandler() {
//        return new LogoutSuccessHandler() {
//            @Override
//            public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                response.sendRedirect("/login");
//            }
//        };
//    }
}
