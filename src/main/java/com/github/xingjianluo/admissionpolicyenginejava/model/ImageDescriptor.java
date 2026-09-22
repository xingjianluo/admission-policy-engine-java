package com.github.xingjianluo.admissionpolicyenginejava.model;

import java.util.List;

/**
 * 统一评估输入：由多种本地工件归一化得到。
 *
 * @param reference       用户请求中给出的镜像引用（repo:tag）
 * @param digest          归一化后的 sha256 指纹，作为工件间一致性锚点
 * @param registry        来源仓库主机
 * @param repository      仓库路径
 * @param tag             标签
 * @param vulnerabilities 扫描漏洞（可能为空列表，但扫描工件必须存在与否由调用方声明）
 * @param provenance      供应链证明，可为 null（表示未提供证明工件）
 * @param signatureValid  签名校验结论，null 表示无签名工件
 */
public record ImageDescriptor(
        String reference,
        String digest,
        String registry,
        String repository,
        String tag,
        List<Vulnerability> vulnerabilities,
        Provenance provenance,
        Boolean signatureValid
) {
}
