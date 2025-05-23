package hcmute.com.ShoeShop.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Builder
@Table(name = "roles")
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int roleId;

    @Column(name = "role_name", nullable = false, unique = true, length = 100)
    @NotNull(message = "Role name must not be null")  // Đảm bảo roleName không null
    @Size(min = 3, max = 100, message = "Role name must be between 3 and 100 characters")
    private String roleName;
}
