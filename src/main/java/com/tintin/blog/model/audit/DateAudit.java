package com.tintin.blog.model.audit;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.Column;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import lombok.Data;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.io.Serializable;
import java.time.Instant;


/*
 * @JsonIgnoreProperties: Chú thích cấp lớp (class) này có thể được sử dụng để loại trừ các thuộc tính nhất định
 * trong quá trình Serialization and Deserialization dữ liệu JSON.
 * Nghĩa là chúng sẽ không được ánh xạ tới nội dung JSON.
 */
@MappedSuperclass // meaning: this class not be entity
@EntityListeners(AuditingEntityListener.class)
@JsonIgnoreProperties(
        value = {"createdAt", "updatedAt"},
        allowGetters = true
)
@Data
public abstract class DateAudit implements Serializable {
    @CreatedDate
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    @Column(nullable = false)
    private Instant updatedAt;
}
