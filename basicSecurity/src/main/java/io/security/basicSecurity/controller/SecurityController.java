package io.security.basicSecurity.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpSession;
import java.util.Map;

@RestController
public class SecurityController {


    @GetMapping(value = "/")
    public String index(HttpSession session) {

//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        SecurityContext context = (SecurityContext) session
//                .getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
//        Authentication authentication1 = context.getAuthentication();

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

//    @GetMapping(value = "/login")
//    public ModelAndView login() {
//        ModelAndView modelAndView = new ModelAndView();
//        modelAndView.setViewName("loginPage");
//
//        return modelAndView;
//    }
//
//    @PostMapping(value = "/login")
//    public ResponseEntity<String> login(@RequestBody Map<String, String> loginData) {
//        String username = loginData.get("username");
//        String password = loginData.get("password");
//
//        if (username.equals("admin") && password.equals("password")) {
//            return ResponseEntity.ok("Successful login");
//        } else {
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username or password");
//        }
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
}
