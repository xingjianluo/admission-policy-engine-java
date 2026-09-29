package com.github.xingjianluo.admissionpolicyenginejava.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** 幂等键/审计 id 派生工具：统一 SHA-256 哈希与空键归一化。 */
final class IdempotencyIds {

    private IdempotencyIds() {
    }

    static String normalizeKey(String idempotencyKey) {
        return idempotencyKey == null || idempotencyKey.isBlank()
                ? "none" : idempotencyKey.trim();
    }

    static String sha256Hex(String raw) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(raw.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }
}
