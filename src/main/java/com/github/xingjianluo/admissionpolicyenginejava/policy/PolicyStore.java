package com.github.xingjianluo.admissionpolicyenginejava.policy;

import java.util.List;

/**
 * 策略版本存储：维护不可变版本链，支持发布新版本与回滚。
 * 所有读取都返回完整一致的 {@link PolicySnapshot}，评估期间即使发生并发更新，
 * 评估线程持有的快照引用也不会变化。
 * <p>
 * 规则 schemaVersion 兼容范围：{@link #SUPPORTED_SCHEMA_MIN} ~ {@link #SUPPORTED_SCHEMA_MAX}。
 */
public interface PolicyStore {

    /** 引擎支持的最低策略 schema 版本（含）。 */
    int SUPPORTED_SCHEMA_MIN = 1;
    /** 引擎支持的最高策略 schema 版本（含）。 */
    int SUPPORTED_SCHEMA_MAX = 2;

    /** 返回当前（最新）策略快照。 */
    PolicySnapshot current();

    /** 按版本号读取快照，不存在时抛 POLICY_VERSION_NOT_FOUND。 */
    PolicySnapshot get(long version);

    /**
     * 基于 expectedBaseVersion 发布新版本；若当前版本已不是 expectedBaseVersion，
     * 抛 POLICY_VERSION_CONFLICT（乐观并发控制）。
     */
    PolicySnapshot publish(long expectedBaseVersion, List<PolicyRule> rules, String by, String comment);

    /** 回滚到指定版本（以该版本规则集创建一个新版本，历史版本链不删除）。 */
    PolicySnapshot rollback(long targetVersion, String by);

    /** 列出全部版本（版本号升序）。 */
    List<PolicySnapshot> history();
}
