package io.security.corespringsecurity.security.handler;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

        String errorMessage = "아이디 혹은 비밀번호가 일치하지 않습니다.";

        if (exception instanceof BadCredentialsException) {
            errorMessage = "아이디 혹은 비밀번호가 일치하지 않습니다.";
        } else if (exception instanceof InsufficientAuthenticationException) {
            errorMessage = "인증에 실패하였습니다. CausedBy : InsufficientAuthenticationException";
        }

        String param = URLEncoder.encode(exception.getMessage(), StandardCharsets.UTF_8);

        setDefaultFailureUrl("/login" + "?error=true&exception=" + param);

        super.onAuthenticationFailure(request, response, exception);
    }
}
