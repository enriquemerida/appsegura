package AplicacionSegura.appsegura;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.ui.Model;
import java.security.Principal;

@Controller
public class MfaController {

    private final MfaService mfaService;

    public MfaController(MfaService mfaService) {
        this.mfaService = mfaService;
    }

    @GetMapping("/mfa")
public String mfaPage(Principal principal, Model model) {
    if (principal != null) {
        try {
            mfaService.generateCode(principal.getName());
            model.addAttribute("info", "Te enviamos un código al correo.");
        } catch (Exception e) {
            model.addAttribute("error", "No se pudo enviar el correo: " + e.getMessage());
        }
    }
    return "mfa";
}


    @PostMapping("/mfa")
public String checkCode(@RequestParam String code, Principal principal, Model model) {
  if (principal != null && mfaService.validateCode(principal.getName(), code)) {
    mfaService.clearCode(principal.getName());
    return "redirect:/hello";
  }
  model.addAttribute("error","Código inválido");
  return "mfa";
}

}
