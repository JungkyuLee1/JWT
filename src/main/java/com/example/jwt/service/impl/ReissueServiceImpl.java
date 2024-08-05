package com.example.jwt.service.impl;

import com.example.jwt.dto.RefreshDto;
import com.example.jwt.dto.TokenDto;
import com.example.jwt.jwt.JWTUtil;
import com.example.jwt.service.RefreshService;
import com.example.jwt.service.ReissueService;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.rmi.server.ExportException;
import java.util.Date;

@Service
public class ReissueServiceImpl implements ReissueService {

    @Autowired
    private JWTUtil jwtUtil;

    @Autowired
    private RefreshService refreshService;

    @Override
    public ResponseEntity reissueToken(String refreshToken) {

        try {
            jwtUtil.isExpired(refreshToken);
        } catch (ExpiredJwtException e) {
            return new ResponseEntity<>("refreshToken expired", HttpStatus.BAD_REQUEST);
        }

        //Token이 refresh 토큰인지 check
        String category = jwtUtil.getCategory(refreshToken);
        if (!category.equals("refresh")) {
            return new ResponseEntity<>("invalid refreshToken", HttpStatus.BAD_REQUEST);
        }

        //DB에 저장되어있는지 확인
        Boolean isExist = refreshService.existsRefresh(refreshToken);
        if (!isExist) {
            return new ResponseEntity<>("token not exists", HttpStatus.BAD_REQUEST);
        }

        //새로운 Access 토큰 발급
        String username = jwtUtil.getUsername(refreshToken);
        String role = jwtUtil.getRole(refreshToken);

        //token 생성(10분, 24시간, access 토큰과 refresh 토큰을 동시에 갱신)
        String newAccessToken = jwtUtil.createJWT("access", username, role, 600000L);
        String newRefreshToken = jwtUtil.createJWT("refresh", username, role, 86400000L);

        //DB에 저장 된 동일 token 삭제 (DB에 허용 시간(24시간) 경과로 expired 된 토큰을 일괄 삭제하는 로직 필요(scheduling))
        refreshService.deleteRefreshToken(refreshToken);
        //Refresh Token DB 저장
        addRefreshToken(username, newRefreshToken, 86400000L);

        TokenDto tokenDto = new TokenDto();
        tokenDto.setAccessToken(newAccessToken);
        tokenDto.setRefreshToken(newRefreshToken);

        return new ResponseEntity<>(tokenDto, HttpStatus.OK);
    }

    private void addRefreshToken(String username, String refreshToken, Long expiredMS) {
        Date date = new Date(System.currentTimeMillis() + expiredMS);

        RefreshDto refreshDto = new RefreshDto();
        refreshDto.setUsername(username);
        refreshDto.setRefreshToken(refreshToken);
        refreshDto.setExpiration(date.toString());

        refreshService.saveRefresh(refreshDto);
    }
}
