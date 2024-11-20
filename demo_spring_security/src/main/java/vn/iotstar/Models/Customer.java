package vn.iotstar.Models;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;


@AllArgsConstructor
@NoArgsConstructor
@Data
@ToString
@Builder
public class Customer {
	private String id;
	private String name;
	private String phoneNumber;
	private String email;

}
