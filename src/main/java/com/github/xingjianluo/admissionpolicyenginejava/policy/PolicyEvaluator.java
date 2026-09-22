package com.github.xingjianluo.admissionpolicyenginejava.policy;

import com.github.xingjianluo.admissionpolicyenginejava.model.DecisionReport;
import com.github.xingjianluo.admissionpolicyenginejava.model.ImageDescriptor;

/** 基于单个不可变策略快照评估镜像，得到可解释结论。 */
public interface PolicyEvaluator {

    DecisionReport evaluate(ImageDescriptor descriptor, PolicySnapshot snapshot);
}
