package hcmute.com.ShoeShop.config;

import hcmute.com.ShoeShop.component.CustomAuthenticationSuccessHandler;
import hcmute.com.ShoeShop.services.imp.CustomUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.servlet.server.ServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.apache.catalina.connector.Connector;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class WebSecurityConfig {
        private final String[] PUBLIC_ENDPOINT = {"/", "/login", "/register", "/product/**", "/category/**", "/send-code", "/reset_password", "/sendcode",
        "/verifycode", "/resetPassword"};
        private final String[] PUBLIC_CSS = {"/assets/**", "/css/**", "/fonts/**", "/img/**", "/js/**", "/lib/**",
                "/style.css", "/uploads/**"};
        @Autowired
        CustomAuthenticationSuccessHandler successHandler;

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
                httpSecurity
                        .cors(AbstractHttpConfigurer::disable)
                        .requiresChannel(channel -> channel.anyRequest().requiresSecure()) // bắt buộc HTTPS
                        .authorizeHttpRequests(request -> request
                                .requestMatchers("/admin/**").hasRole("admin")
                                .requestMatchers("/manager/**").hasAnyRole("manager", "admin")
                                .requestMatchers("/shipper/**").hasRole("shipper")
                                .requestMatchers(PUBLIC_ENDPOINT).permitAll()
                                .requestMatchers(PUBLIC_CSS).permitAll() // Cho phép truy cập tài nguyên tĩnh
                                .anyRequest().authenticated())
                        //config cho trang login
                        .formLogin(formLogin ->
                                formLogin.loginPage("/login")
                                        .successHandler(successHandler)
                                        .failureHandler(new SimpleUrlAuthenticationFailureHandler("/login?error=true"))
                                        .permitAll()
                        )
                        //config cho trang logout
                        .logout(logout ->
                                logout.logoutUrl("/logout").permitAll()
                        )
                        .exceptionHandling(exception -> exception
                                .accessDeniedHandler(accessDeniedHandler()))
                        .headers(headers -> headers
                                .httpStrictTransportSecurity(hsts -> hsts
                                        .includeSubDomains(true)
                                        .maxAgeInSeconds(31536000))
                                .contentTypeOptions(Customizer.withDefaults())
                        );
                //cai nay tu bat nen phai tat
                //httpSecurity.csrf(AbstractHttpConfigurer::disable);
                return httpSecurity.build();
        }


        @Bean
        public PasswordEncoder passwordEncoder() {
                return new BCryptPasswordEncoder();
        }

        @Bean
        public UserDetailsService userDetailsService() {
                return new CustomUserDetailService();
        }

        @Bean
        public AccessDeniedHandler accessDeniedHandler() {
                return (request, response, accessDeniedException) -> {
                        // Chuyển hướng đến trang thông báo
                        response.sendRedirect("/access-denied");
                };
        }

        @Bean
        public ServletWebServerFactory servletContainer() {
                TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory();
                tomcat.addAdditionalTomcatConnectors(redirectConnector());
                return tomcat;
        }
        private Connector redirectConnector() {
                Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
                connector.setScheme("http");
                connector.setPort(8080); // Port HTTP
                connector.setSecure(false);
                connector.setRedirectPort(8443); // Redirect sang HTTPS port
                return connector;
        }
}
