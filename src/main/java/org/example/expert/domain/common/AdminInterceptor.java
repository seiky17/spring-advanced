package org.example.expert.domain.common;


import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.expert.config.JwtUtil;
import org.example.expert.domain.user.enums.UserRole;

import org.hibernate.validator.internal.IgnoreForbiddenApisErrors;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.time.LocalDateTime;
import java.util.logging.Level;
import java.util.logging.Logger;

@Component
@RequiredArgsConstructor
public class AdminInterceptor implements HandlerInterceptor {

    private final JwtUtil jwtUtil;
    private static final Logger log = Logger.getLogger(AdminInterceptor.class.getName());

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

        String bearerJwt = request.getHeader("Authorization");
        String jwt = jwtUtil.substringToken(bearerJwt);
        Claims claims = jwtUtil.extractClaims(jwt);

        UserRole userRole = UserRole.valueOf(claims.get("userRole", String.class));

        if(!UserRole.ADMIN.equals(userRole)) {
            log.log(Level.SEVERE, "관리자 권한이 없습니다!");
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "관리자 권한이 없습니다.");
            return false;
        }

        log.log(Level.INFO, "[Request] : {0}", request.getRequestURI());
        log.log(Level.INFO, "[RequestTime] : {0}", LocalDateTime.now());

        return true;
    }
}