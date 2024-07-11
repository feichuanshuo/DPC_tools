import json
from simpletransformers.classification import ClassificationModel
from utils.policy_analysis.policy_structure_parser import policy_structure_parser
from resources.configuration import bert_pc_model


policy_sentences_path = "./cache/policy_sentences.json"


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
    pc_model = ClassificationModel('bert', bert_pc_model)
    for sentence_item in parsed_sentences:
        if sentence_item["privacy_category"] is None:
            sentence = sentence_item["sentence"]
            pc_predictions, raw_outputs = pc_model.predict([sentence])
            sentence_item["privacy_category"] = str(pc_predictions[0])


if __name__ == '__main__':
    policy_analysis("../../example/抖音隐私政策.txt")