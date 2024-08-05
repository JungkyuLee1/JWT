package com.example.jwt.jwt;

import com.example.jwt.dto.CustomUserDetails;
import com.example.jwt.dto.UserDto;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;

//해당 필터를 통해 요청 헤더 Authorization 키에 JWT가 존재하는 경우 JWT를 검증하고 강제로 SecurityContextHolder에서
//세션을 생성한다.(이 session은 Stateless 상태로 관리되기 때문에 해당 요청이 끝나면 소멸 된다.)
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //헤더에서 access 키에 담긴 토큰을 꺼냄
        String accessToken = request.getHeader("access");

        //토근이 없다면 다음 필터로 넘김
        if (accessToken == null) {
            filterChain.doFilter(request, response);
            return;
        }

        //토큰 만료여부 확인, 만료시 다음 필터로 넘기지 않음
        try {
            jwtUtil.isExpired(accessToken);
        } catch (ExpiredJwtException e) {
            PrintWriter writer = response.getWriter();
            writer.print("access token expired");

            //response status code(Send code by client's request)
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        //Token이 payload인지 확인(발급 시 payload에 명시)
        String category = jwtUtil.getCategory(accessToken);

        if (!category.equals("access")) {
            //response body
            PrintWriter writer = response.getWriter();
            writer.print("invalid access token");

            //response status code
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        //username, role 값을 획득
        String username = jwtUtil.getUsername(accessToken);
        String role = jwtUtil.getRole(accessToken);

        UserDto newUser = new UserDto();
        newUser.setUsername(username);
        newUser.setRole(role);

        CustomUserDetails customUserDetails = new CustomUserDetails(newUser);
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
        //session 생성
        SecurityContextHolder.getContext().setAuthentication(authToken);
        filterChain.doFilter(request, response);


//        //Single token 발급 경우
//        //request에서 Authorization Header 찾음
//        String authorization = request.getHeader("Authorization");
//
//        //Authorization Header 검증
//        if (authorization == null || !authorization.startsWith("Bearer ")) {
//            System.out.println("token null");
//            //다음 filter로 넘감
//            filterChain.doFilter(request, response);
//            return;
//        }
//
//        //Bearer 부분 제거 후 순수 token 획득
//        String token = authorization.split(" ")[1];
//
//        if (jwtUtil.isExpired(token)) {
//            System.out.println("token expired!");
//            filterChain.doFilter(request, response);
//            return;
//        }
//
//        //token에서 username, role 획득
//        String username = jwtUtil.getUsername(token);
//        String role = jwtUtil.getRole(token);
//
//        UserDto newUser = new UserDto();
//        newUser.setUsername(username);
//        newUser.setPassword("tempPassword");
//        newUser.setRole(role);
//
//        CustomUserDetails customUserDetails = new CustomUserDetails(newUser);
//        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
//
//        //session 생성
//        SecurityContextHolder.getContext().setAuthentication(authToken);
//        filterChain.doFilter(request, response);
    }
}
