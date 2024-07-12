import json

from utils.policy_analysis.policy_structure_parser import policy_structure_parser
from utils.policy_analysis.policy_sentences_classification import policy_sentences_classification

policy_analysis_result_dir = "utils/policy_analysis/policy_analysis_result.json"


def policy_analysis(policy_path):
    """
    隐私政策解析
    :param policy_path: 隐私政策路径
    """
    parser = policy_structure_parser(policy_path)
    if parser.parse_privacy_policy():
        parsed_sentences = parser.parsed_sentences_with_PC
    else:
        print(parser.parse_error_info)
        return
    parsed_sentences = policy_sentences_classification(parsed_sentences)

    result = {'CR1': False, 'CR2': False, 'CR3': False, 'CR4': False, 'CR5': False, 'CR6': False, 'CR7': False,
              'CR8': False, 'CR9': False, 'CR10': False, 'CR11': False, 'CR12': False, 'CR13': False, 'CR14': False,
              'CR15': False, 'CR16': False, 'CR17': False, 'CR18': False, 'CR19': False, 'CR20': False, 'CR21': False,
              'CR22': False, 'CR23': False, 'CR24': False, 'CR25': False, 'CR26': False}

    for sentence_item in parsed_sentences:
        for cr in sentence_item["compliance_rules"]:
            result["CR" + cr] = True

    with open(policy_analysis_result_dir, 'w', encoding='utf-8') as f:
        json.dump(parsed_sentences, f, ensure_ascii=False, indent=4)

    return result


if __name__ == '__main__':
    policy_analysis("../../example/抖音隐私政策.txt")
