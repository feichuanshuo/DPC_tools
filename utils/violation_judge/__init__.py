"""
违规判定
"""
import json
from utils.violation_judge.extract_DPIS import extract_DPIS, judge_keyword_equal_text
from configuration import parsed_policy_dir,DPIS_dir
from  utils.violation_judge.violation_analysis import violation_analysis


import hanlp
tok = hanlp.load(hanlp.pretrained.tok.COARSE_ELECTRA_SMALL_ZH)
pos = hanlp.load(hanlp.pretrained.pos.CTB9_POS_ELECTRA_SMALL)

def violation_judge():
    has_ETC = False
    # 声明的个人信息集
    DPIS = {}
    # 获取解析后的隐私政策
    with open(parsed_policy_dir, 'r', encoding='utf-8') as f:
        parsed_policy = json.load(f)
    # 提取隐私政策中声明的个人信息集
    for sentence_item in parsed_policy:
        if '13' in sentence_item['compliance_rules']:
            extract_DPIS(sentence_item['sentence'], DPIS)
            # ETC检测
            sentence = tok(sentence_item['sentence'])
            pos_res = pos(sentence)
            if 'ETC' in pos_res:
                ETC_index = pos_res.index('ETC')
                flag_equal_texts, key = judge_keyword_equal_text(sentence[ETC_index-1])
                if flag_equal_texts:
                    has_ETC = True

    # 保存DPIS
    with open(DPIS_dir, 'w', encoding='utf-8') as f:
        json.dump(DPIS, f, ensure_ascii=False, indent=4)

    return violation_analysis(has_ETC)
