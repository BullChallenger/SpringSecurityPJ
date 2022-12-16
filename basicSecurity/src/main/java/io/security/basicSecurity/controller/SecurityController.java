package io.security.basicSecurity.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

@RestController
public class SecurityController {


    @GetMapping(value = "/")
    public String index(HttpSession session) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        SecurityContext context = (SecurityContext) session
                .getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication1 = context.getAuthentication();

        return "home";
    }

    @GetMapping(value = "/thread")
    public String thread() {

        new Thread(

                new Runnable() {
                    @Override
                    public void run() {
                        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                    }
                }

        ).start();

        return "thread";
    }

//    csrf_token 없이 POST와 같은 HTTP 메소드로 접근 시 403 오류 발생
//    @PostMapping(value = "/")
//    public String postHome() {
//
//        return "home";
//    }

//    @GetMapping(value = "loginPage")
//    public String loginPage() {
//
//        return "loginPage";
//    }

    @GetMapping("/user")
    public String user() {

        return "user";
    }

    @GetMapping("/admin")
    public String admin() {

        return "admin";
    }

    @GetMapping("/admin/pay")
    public String adminPay() {

        return "adminPay";
    }

    @GetMapping(value = "/denied")
    public String denied() {

        return "Access is denied";
    }

//    @GetMapping(value = "/login")
//    public String login() {
//
//        return "login";
//    }

}
