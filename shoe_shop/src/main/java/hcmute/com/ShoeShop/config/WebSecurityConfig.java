package hcmute.com.ShoeShop.config;

import hcmute.com.ShoeShop.component.CustomAuthenticationFailureHandler;
import hcmute.com.ShoeShop.component.CustomAuthenticationSuccessHandler;
import hcmute.com.ShoeShop.services.imp.CustomUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

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

        @Autowired
        CustomAuthenticationFailureHandler failureHandler;

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
                httpSecurity.authorizeHttpRequests(request -> request
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
                                        .failureHandler(failureHandler)
                                        .permitAll()
                        )
                        // Cấu hình quản lý phiên đăng nhập
                        .sessionManagement(session -> session
                                .sessionFixation(sessionFixation -> sessionFixation
                                        .newSession() // Tạo session mới sau khi đăng nhập (chống session fixation)
                                )
                                .invalidSessionUrl("/login?session=invalid") // Chuyển hướng khi session không hợp lệ
                                .maximumSessions(1) // Chỉ cho phép 1 session đăng nhập tại 1 thời điểm
                                .maxSessionsPreventsLogin(false) // Cho phep login o trinh duyet khac, login cu se bi xoa
                        )
                        //config cho trang logout
                        .logout(logout ->
                                logout
                                        .invalidateHttpSession(true) // Hủy session
                                        .deleteCookies("JSESSIONID") // xóa cookie
                                        .logoutUrl("/logout")
                                        .permitAll()
                        )
                        .exceptionHandling(exception -> exception
                                .accessDeniedHandler(accessDeniedHandler())
                        )
                        .headers(headers -> headers
                                .contentSecurityPolicy(csp -> csp
                                        .policyDirectives(
                                                "default-src 'self'; " +
                                                        "script-src 'self'; " +  // Cho phép inline scripts
                                                        "style-src 'self' https://fonts.googleapis.com; " +  // Cho phép inline styles
                                                        "img-src 'self' https://localhost:8443 data:; " +
                                                        "font-src 'self' data: https://fonts.gstatic.com; " +
                                                        "frame-ancestors 'none'; " +
                                                        "form-action 'self'; " +
                                                        "base-uri 'self'; " +
                                                        "object-src 'none'; " +
                                                        "upgrade-insecure-requests;"
                                        )
                                )
                                .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny  // Chống clickjacking
                                )
                                .xssProtection(xss -> {}// Bật XSS protection
                                )
                                .contentTypeOptions(content -> {})  // Ngăn MIME type sniffing
                        );
                //cai nay tu bat nen phai tat
                //httpSecurity.csrf(AbstractHttpConfigurer::disable);
                return httpSecurity.build();
        }

        @Bean
        public AuthenticationEntryPoint authenticationEntryPoint() {
                return (request, response, authException) -> {
                        response.sendRedirect("/login?error=true");
                };
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
}
