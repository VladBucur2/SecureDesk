package nl.fontys.securedesk.common;

import org.springframework.data.domain.Page;

import java.util.List;
import java.util.function.Function;

/** Every list is paginated, with a hard maximum page size (SC-10). */
public record PageResponse<T>(List<T> items, int page, int size, long total) {

    public static final int MAX_SIZE = 50;

    public static <E, T> PageResponse<T> of(Page<E> page, Function<E, T> mapper) {
        return new PageResponse<>(page.getContent().stream().map(mapper).toList(),
                page.getNumber(), page.getSize(), page.getTotalElements());
    }
}
