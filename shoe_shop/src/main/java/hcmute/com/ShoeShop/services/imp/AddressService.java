package hcmute.com.ShoeShop.services.imp;

import hcmute.com.ShoeShop.entity.Address;
import hcmute.com.ShoeShop.repository.AddressRepository;
import hcmute.com.ShoeShop.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AddressService {
    @Autowired
    private AddressRepository addressRepository;
    @Autowired
    private UserRepository userRepository;

    public void save(Address address) {
        addressRepository.save(address);
    }

    public List<Address> findAll() {
        return addressRepository.findAll();
    }

    public void delete(Address address) {
        addressRepository.delete(address);
    }

    // Tìm địa chỉ theo ID
    public Address findById(Integer addressId) {
        return addressRepository.findById(addressId).orElse(null);
    }

    public List<Address> getAddressesByID(int id) {
        return addressRepository.findByUserId(id);
    }

    //Mục đích là chỉ có 1 cái default
    public void setDefaultAddress(int userId, int addressId) {
        // Đặt tất cả các địa chỉ của user về false
        List<Address> userAddresses = addressRepository.findByUserId(userId);
        for (Address address : userAddresses) {
            if (address.getIsDefault() != null && address.getIsDefault()) {
                address.setIsDefault(false);
                addressRepository.save(address);
            }
        }

        // Đặt địa chỉ mới là default
        Address newDefaultAddress = addressRepository.findById(addressId)
                .orElseThrow(() -> new IllegalArgumentException("Address not found with id: " + addressId));
        newDefaultAddress.setIsDefault(true);
        addressRepository.save(newDefaultAddress);
    }

}
