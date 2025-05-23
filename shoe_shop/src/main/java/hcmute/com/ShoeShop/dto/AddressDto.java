package hcmute.com.ShoeShop.dto;

import hcmute.com.ShoeShop.entity.Users;
import lombok.Data;

@Data
public class AddressDto {
        private int id;
        private String address;
        private Boolean isDefault = false;
        private Users user;
}
