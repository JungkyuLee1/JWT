package com.example.jwt.controller;

import com.example.jwt.dto.TokenDto;
import com.example.jwt.service.ReissueService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/")
public class ReissueController {

    @Autowired
    private ReissueService reissueService;

    @PostMapping("/reissue")
    public ResponseEntity reissueToken(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = null;

        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("refresh")) {
                refreshToken = cookie.getValue();
            }
        }

        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("refresh token null");
        }

        ResponseEntity respond = reissueService.reissueToken(refreshToken);

        if (respond.getStatusCode().is2xxSuccessful()) {
            TokenDto tokenDto = (TokenDto) respond.getBody();

            response.setHeader("access", tokenDto.getAccessToken());
            response.addCookie(createCookie("refresh", tokenDto.getRefreshToken()));

            return ResponseEntity.status(HttpStatus.OK).build();
        } else {
            return respond;
        }
    }

    private Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24 * 60 * 60); //24시간
//        cookie.setSecure(true);
//        cookie.setPath("/");
        cookie.setHttpOnly(true);

        return cookie;
    }
}
