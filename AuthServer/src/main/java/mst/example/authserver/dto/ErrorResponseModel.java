package mst.example.authserver.dto;

import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
@Getter
@Setter
public class ErrorResponseModel {

    private String message;
    private String description;
}