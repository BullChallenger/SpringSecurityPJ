package io.security.corespringsecurity.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

        String errMsg = "유효하지 않은 ID 혹은 비밀번호 입니다.";

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        if (exception instanceof BadCredentialsException) {
            errMsg = "아이디 혹은 비밀번호가 일치하지 않습니다.";
        } else if (exception instanceof InsufficientAuthenticationException) {
            errMsg = "인증에 실패하였습니다. CausedBy : InsufficientAuthenticationException";
        } else if (exception instanceof DisabledException) {
            errMsg = "Locked";
        } else if (exception instanceof CredentialsExpiredException) {
            errMsg = "Expired password";
        }

        objectMapper.writeValue(response.getWriter(), errMsg);
    }
}
