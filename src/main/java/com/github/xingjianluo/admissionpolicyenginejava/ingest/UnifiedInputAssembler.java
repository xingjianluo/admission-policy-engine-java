package com.github.xingjianluo.admissionpolicyenginejava.ingest;

import com.github.xingjianluo.admissionpolicyenginejava.exception.IngestException;
import com.github.xingjianluo.admissionpolicyenginejava.model.AdmissionRequest;
import com.github.xingjianluo.admissionpolicyenginejava.model.ImageMetadata;
import com.github.xingjianluo.admissionpolicyenginejava.model.Provenance;
import com.github.xingjianluo.admissionpolicyenginejava.model.ScanReport;
import org.springframework.stereotype.Component;

import java.nio.file.Path;

/**
 * 将本地镜像清单、扫描结果、供应链证明装配为统一评估输入。
 *
 * <p>关键保证：
 * <ul>
 *   <li>任一来源缺失（null 路径）→ MISSING_SOURCE，不得静默跳过；</li>
 *   <li>三处镜像指纹（digest）必须完全一致，否则 FINGERPRINT_MISMATCH；</li>
 *   <li>requestId 不能为空，用于审计幂等去重。</li>
 * </ul>
 */
@Component
public class UnifiedInputAssembler {

    private final LocalManifestReader manifestReader;
    private final LocalScanReportReader scanReader;
    private final LocalProvenanceReader provenanceReader;

    public UnifiedInputAssembler(LocalManifestReader manifestReader,
                                 LocalScanReportReader scanReader,
                                 LocalProvenanceReader provenanceReader) {
        this.manifestReader = manifestReader;
        this.scanReader = scanReader;
        this.provenanceReader = provenanceReader;
    }

    public AdmissionRequest assemble(String requestId,
                                     Path manifestFile,
                                     Path scanFile,
                                     Path provenanceFile) {
        if (requestId == null || requestId.isBlank()) {
            throw new IngestException(IngestFailureReason.MISSING_REQUIRED_FIELD,
                    null, "requestId must not be blank");
        }
        if (manifestFile == null) {
            throw new IngestException(IngestFailureReason.MISSING_SOURCE,
                    null, "manifest source is not provided");
        }
        if (scanFile == null) {
            throw new IngestException(IngestFailureReason.MISSING_SOURCE,
                    null, "scan report source is not provided");
        }
        if (provenanceFile == null) {
            throw new IngestException(IngestFailureReason.MISSING_SOURCE,
                    null, "provenance source is not provided");
        }

        ImageMetadata metadata = manifestReader.read(manifestFile);
        ScanReport scan = scanReader.read(scanFile);
        Provenance provenance = provenanceReader.read(provenanceFile);

        String manifestDigest = metadata.digest();
        if (!manifestDigest.equals(scan.imageDigest())) {
            throw new IngestException(IngestFailureReason.FINGERPRINT_MISMATCH,
                    scanFile.toString(),
                    "scan report digest " + scan.imageDigest()
                            + " does not match manifest digest " + manifestDigest);
        }
        if (!manifestDigest.equals(provenance.imageDigest())) {
            throw new IngestException(IngestFailureReason.FINGERPRINT_MISMATCH,
                    provenanceFile.toString(),
                    "provenance subject digest " + provenance.imageDigest()
                            + " does not match manifest digest " + manifestDigest);
        }

        return new AdmissionRequest(requestId, metadata, scan, provenance);
    }
}
