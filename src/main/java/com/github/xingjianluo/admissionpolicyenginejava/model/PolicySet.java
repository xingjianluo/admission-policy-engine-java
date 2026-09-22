package com.github.xingjianluo.admissionpolicyenginejava.model;

import java.util.List;

/**
 * 某一版本的不可变策略集合。
 *
 * <p>版本兼容：策略文件带 schemaVersion，评估器只接受
 * [MIN_SUPPORTED_SCHEMA, CURRENT_SCHEMA] 区间内的版本，区间外一律拒绝加载。
 */
public record PolicySet(long version,
                        int schemaVersion,
                        List<PolicyRule> rules,
                        long createdAtEpochMs,
                        String changeComment) {

    /** 当前策略结构版本。 */
    public static final int CURRENT_SCHEMA = 1;
    /** 向后兼容的最低策略结构版本。 */
    public static final int MIN_SUPPORTED_SCHEMA = 1;

    public PolicySet {
        rules = rules == null ? List.of() : List.copyOf(rules);
        changeComment = changeComment == null ? "" : changeComment;
    }

    public static boolean isSchemaSupported(int schemaVersion) {
        return schemaVersion >= MIN_SUPPORTED_SCHEMA && schemaVersion <= CURRENT_SCHEMA;
    }
}
