package com.github.xingjianluo.admissionpolicyenginejava.model;

import com.github.xingjianluo.admissionpolicyenginejava.ingest.IngestionRequest;

/**
 * 批量操作中的单个镜像输入项（与具体 HTTP DTO 解耦）。
 *
 * @param index   该项在批量请求中的下标（从 0 开始，用于结果对位）
 * @param request 单个镜像的工件摄入请求，合法时非 null；
 *                若 Web 层在组装阶段就判定该项结构非法，可为 null
 * @param requestError 结构非法时的说明（与 request 互斥使用），合法时为 null
 */
public record BatchItemInput(
        int index,
        IngestionRequest request,
        String requestError
) {
}
