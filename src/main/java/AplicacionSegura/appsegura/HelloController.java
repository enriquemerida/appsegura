package AplicacionSegura.appsegura;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

@Controller
public class HelloController {

    @GetMapping("/hello")
    public String hello(Principal principal, Model model) {
        model.addAttribute("user", principal.getName());
        return "inicio";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }
}
