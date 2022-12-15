package io.security.basicSecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    @GetMapping(value = "/")
    public String index() {

        return "home";
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
