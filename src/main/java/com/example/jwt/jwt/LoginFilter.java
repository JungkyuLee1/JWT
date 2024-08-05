package com.example.jwt.jwt;

import com.example.jwt.dto.CustomUserDetails;
import com.example.jwt.dto.RefreshDto;
import com.example.jwt.service.RefreshService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

//무조건 자동으로 실행 됨(Springboot mechanism(UsernamePasswordAuthenticationFilter))
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    private final JWTUtil jwtUtil;
    private final RefreshService refreshService;

    public LoginFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil, RefreshService refreshService) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.refreshService = refreshService;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        //1.가로채기 (username, password)
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        System.out.println("username :" + username);
        System.out.println("password :" + password);

        //2.인증 진행 준비(UsernamePasswordAuthenticationToken에 담기, null = role 값(임시))
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);
        //3.AuthenticationManager 에서 검증 진행
        return authenticationManager.authenticate(authToken);

        //4.Security Config 에 등록해서 범용적 사용
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        //선택 가능(username)
        //CustomUserDetails customUserDetails = (CustomUserDetails) authResult.getPrincipal();
        //String username = customUserDetails.getUsername();

        //DB에서 읽어온 UserDetails 정보를 Authentication Manager 가 handling 하여 내부 보관 상태 : Provider Manager 가 완료 통보 역할
        String username = authResult.getName();
        Collection<? extends GrantedAuthority> authorities = authResult.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        //token 생성(10분, 24시간)
        String access = jwtUtil.createJWT("access", username, role, 600000L);
        String refresh = jwtUtil.createJWT("refresh", username, role, 86400000L);

        //refreshToken 저장
        addRefreshToken(username,refresh,86400000L);

        //client : access token은 local에 저장, refresh token은 cookie에 저장
        response.setHeader("access", access);
        response.addCookie(createCookie("refresh", refresh));
        response.setStatus(HttpStatus.OK.value());


        //Single token 발급 경우
//        CustomUserDetails customUserDetails = (CustomUserDetails) authResult.getPrincipal();
//        String username = customUserDetails.getUsername();
//
//        Collection<? extends GrantedAuthority> authorities = authResult.getAuthorities();
//        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
//        GrantedAuthority auth = iterator.next();
//
//        String role = auth.getAuthority();
//
//        String token = jwtUtil.createJWT(username, role, 1000 * 60 * 15);
////        String token= jwtUtil.createJWT(username, role, 60*60*10L); //10시간
////        expTime.setTime(expTime.getTime() + 1000 * 60 * 15); //15분
//
//        //1.Header로 보내기
//        response.addHeader("Authorization", "Bearer " + token);
//
////        //2.Cookie로 보내기
////        Cookie cookie =new Cookie("token", token);
////        cookie.setHttpOnly(true);
////        cookie.setPath("/");
////
////        response.addCookie(cookie);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        super.unsuccessfulAuthentication(request, response, failed);

        response.setStatus(401);
    }

    private void addRefreshToken(String username, String refreshToken, Long expiredMs){
        Date date=new Date(System.currentTimeMillis() + expiredMs);

        RefreshDto refreshDto = new RefreshDto();
        refreshDto.setUsername(username);
        refreshDto.setRefreshToken(refreshToken);
        refreshDto.setExpiration(date.toString());

        refreshService.saveRefresh(refreshDto);
    }

    private Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24 * 60 * 60); //24시간
//        cookie.setSecure(true); //https
//        cookie.setPath("/");
        cookie.setHttpOnly(true);

        return cookie;
    }
}
