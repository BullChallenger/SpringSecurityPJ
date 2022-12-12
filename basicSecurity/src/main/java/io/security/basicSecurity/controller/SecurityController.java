package io.security.basicSecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    @GetMapping(value = "/")
    public String index() {

        return "home";
    }

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

}
