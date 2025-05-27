package hcmute.com.ShoeShop.services.imp;

import hcmute.com.ShoeShop.component.LoginAttemptService;
import hcmute.com.ShoeShop.entity.Users;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailService implements UserDetailsService {
    @Autowired
    UserService userService;

    @Autowired
    private LoginAttemptService loginAttemptService;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Users user = userService.findUserByEmail(email);
        if (user == null) {
            throw new UsernameNotFoundException("can not find email");
        }

        // Kiểm tra xem tài khoản có đang bị khóa không
        if (loginAttemptService.isBlocked(email)) {
            throw new LockedException("Tài khoản bị tạm khóa do đăng nhập sai nhiều lần. Vui lòng thử lại sau.");
        }

        return User.builder()
                .username(user.getEmail())
                .password(user.getPass())
                .roles(user.getRole().getRoleName())
                .build();
    }
}
