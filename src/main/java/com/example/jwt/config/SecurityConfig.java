package com.example.jwt.config;

import com.example.jwt.jwt.CustomLogoutFilter;
import com.example.jwt.jwt.JWTFilter;
import com.example.jwt.jwt.JWTUtil;
import com.example.jwt.jwt.LoginFilter;
import com.example.jwt.service.RefreshService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


    private final AuthenticationConfiguration authenticationConfiguration;
    private final JWTUtil jwtUtil;
    private final RefreshService refreshService;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JWTUtil jwtUtil, RefreshService refreshService) {
        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
        this.refreshService = refreshService;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }


    //비밀번호를 cache로 암호화하여 검증 진행 함 (BCryptPasswordEncorder로 암호화 할 수 있음)
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        //CORS 문제 해소
        http.cors((cors) -> cors.configurationSource(new CorsConfigurationSource() {
            @Override
            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                CorsConfiguration configuration = new CorsConfiguration();

                configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                configuration.setAllowedMethods(Collections.singletonList("*"));
                configuration.setAllowCredentials(true);
                configuration.setAllowedHeaders(Collections.singletonList("*"));
                configuration.setMaxAge(3600L);

                configuration.setExposedHeaders(Collections.singletonList("Authorization"));

                return configuration;
            }
        }));


        //Session 방식에서는 Session 이 항상 고정되어 있으므로 csrf 공격방어 필요(But, jwt 방식에서는 Session 을 stateless 상태로 관리 함으로..)
        http.csrf((auth) -> auth.disable());
        //Form login 방식 disable (JWT 로그인 방식 사용 때문)
        http.formLogin((auth) -> auth.disable());
        //http basic 인증방식 disable (JWT 로그인 방식 사용 때문)
        http.httpBasic((auth) -> auth.disable());

        //1.login,root(/),join 경로에 대하여는 모든 권한 허용(누구나 접근 가능)
        //2.admin 경로는 ADMIN 권한을 가진 사용자만 접근 가능(token에 권한 정보 있음)
        //3.그외는 로그인한 사용자만 접근 가능(authenticated)
        http.authorizeHttpRequests((auth) -> auth.requestMatchers("/login", "/", "/join", "/reissue")
                .permitAll().requestMatchers("/admin").hasRole("ADMIN").anyRequest().authenticated());

        //JWTFilter 등록
        http.addFilterBefore(new JWTFilter(jwtUtil), LoginFilter.class);
        //LoginFilter 등록 (UsernamePasswordAuthenticationFilter.class <-등록 위치)
        http.addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil, refreshService), UsernamePasswordAuthenticationFilter.class);

        //Logout filter 등록 ("/logout" 경로는 default로 인식 함, 별도 지정 불필요)
        http.addFilterBefore(new CustomLogoutFilter(jwtUtil, refreshService), LogoutFilter.class);
        //Jwt 방식에서는 session 을 stateless 상태로 설정(중요)
        http.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}

//1.SecurityConfig 의 /login 에 의하여 LoginFilter 실행
//2.CustomUserDetailsService 자동 싷행 (임의로 생성 된 CustomUserDetailsService 는 AuthenticationManagerBuilder를 통하여 자동 등록 처리 됨)
//3.LoginFilter success / unsuccess 부분 실행
//4.Session 이 만들어 짐
//위 1,2,3,4는 Controller 수행 전 먼저 수행(가로채서..)