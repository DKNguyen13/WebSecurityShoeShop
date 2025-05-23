package hcmute.com.ShoeShop.services.imp;

import hcmute.com.ShoeShop.entity.Users;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailService implements UserDetailsService {
    @Autowired
    UserService userService;
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Users user = userService.findUserByEmail(email);
        if (user == null) {
            throw new UsernameNotFoundException("can not find email");
        }
        return User.builder()
                .username(user.getEmail())
                .password(user.getPass())
                .roles(user.getRole().getRoleName())
                .build();
    }
}
