package hcmute.com.ShoeShop.config;

import hcmute.com.ShoeShop.entity.Role;
import hcmute.com.ShoeShop.entity.Users;
import hcmute.com.ShoeShop.repository.RoleRepository;
import hcmute.com.ShoeShop.repository.UserRepository;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import java.util.List;

@Configuration
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
public class ApplicationInitConfig {

    PasswordEncoder passwordEncoder;
    @Bean
    ApplicationRunner applicationRunner(UserRepository userRepository, RoleRepository roleRepository) {
        return args -> {
            // Danh sách role mặc định
            List<String> roles = List.of("admin", "manager", "user", "shipper");

            // Kiểm tra và tạo các role nếu chưa tồn tại
            roles.forEach(roleName -> {
                if (roleRepository.findRoleByRoleName(roleName) == null) {
                    Role role = Role.builder().roleName(roleName).build();
                    roleRepository.save(role);
                    log.info("Role '{}' has been created.", roleName);
                }
            });
            if (userRepository.findByEmail("admin@admin") == null) {

                Users user = Users.builder()
                        .email("admin@admin")
                        .role(roleRepository.findRoleByRoleName("admin"))
                        .pass(passwordEncoder.encode("123123"))
                        .address("admin")
                        .fullname("admin")
                        .address("1 VNN, TP Thu Duc, VN")
                        .phone("0123456789")
                        .build();
                userRepository.save(user);
                log.warn("Admin user has been created with default email:admin@admin password:123123 , please change it");
            }
        };
    }
}
