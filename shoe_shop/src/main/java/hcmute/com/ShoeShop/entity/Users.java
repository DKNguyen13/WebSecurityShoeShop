package hcmute.com.ShoeShop.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users")
@Builder
public class Users {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private int id;

        @NotNull(message = "Fullname cannot be null")
        @Size(min = 1, max = 100, message = "Fullname must be between 1 and 100 characters")
        @Column(name = "fullname", nullable = false, length = 100)
        private String fullname;

        @NotNull(message = "Email cannot be null")
        @Email(message = "Email should be valid")
        @Size(max = 100, message = "Email cannot exceed 100 characters")
        @Column(name = "email", nullable = false, unique = true, length = 100)
        private String email;

        @NotNull(message = "Password cannot be null")
        @Size(min = 6, message = "Password must have at least 6 characters")
        @Column(name = "pass", nullable = false)
        private String pass;

        @NotNull(message = "Address cannot be null")
        @Size(max = 255, message = "Address cannot exceed 255 characters")
        @Column(name = "address", length = 255, nullable = false)
        private String address;

        @NotNull(message = "Phone number cannot be null")
        @Pattern(regexp = "^0\\d{9}$", message = "Phone number must be a valid 10-digit number starting with 0")
        @Column(name = "phone", nullable = false, length = 10)
        private String phone;

        @ManyToOne  // Một người dùng chỉ có một vai trò
        @JoinColumn(name = "role_id", nullable = false)
        private Role role;

        // Quan hệ OneToMany với Rating
        @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
        private List<Rating> ratings = new ArrayList<>();


        @Override
        public String toString() {
                return "Users{" +
                        "role=" + role +
                        ", phone='" + phone + '\'' +
                        ", address='" + address + '\'' +
                        ", pass='" + pass + '\'' +
                        ", email='" + email + '\'' +
                        ", fullname='" + fullname + '\'' +
                        ", id=" + id +
                        '}';
        }
}
