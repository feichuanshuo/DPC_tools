"""
隐私政策句子分类
"""
import os

import torch
from simpletransformers.classification import ClassificationModel
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from configuration import bert_pc_model, bert_cr_model



class CRModel:
    def __init__(self, model_path):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = AutoModelForSequenceClassification.from_pretrained(model_path).to(self.device)
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)

    def predict(self, text):
        inputs = self.tokenizer(text, return_tensors='pt', padding=True, truncation=True, max_length=512)
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        with torch.no_grad():
            outputs = self.model(**inputs)
        logits = outputs.logits
        res = torch.argmax(logits, dim=-1).item()
        return res

# 加载模型
pc_model = ClassificationModel('bert', bert_pc_model)

cr1_model = CRModel(os.path.join(bert_cr_model, "CR_1"))
cr2_model = CRModel(os.path.join(bert_cr_model, "CR_2"))
cr3_model = CRModel(os.path.join(bert_cr_model, "CR_3"))
cr4_model = CRModel(os.path.join(bert_cr_model, "CR_4"))
cr5_model = CRModel(os.path.join(bert_cr_model, "CR_5"))
cr6_model = CRModel(os.path.join(bert_cr_model, "CR_6"))
cr7_model = CRModel(os.path.join(bert_cr_model, "CR_7"))
cr8_model = CRModel(os.path.join(bert_cr_model, "CR_8"))
cr9_model = CRModel(os.path.join(bert_cr_model, "CR_9"))
cr10_model = CRModel(os.path.join(bert_cr_model, "CR_10"))
cr11_model = CRModel(os.path.join(bert_cr_model, "CR_11"))
cr12_model = CRModel(os.path.join(bert_cr_model, "CR_12"))
cr13_model = CRModel(os.path.join(bert_cr_model, "CR_13"))
cr14_model = CRModel(os.path.join(bert_cr_model, "CR_14"))
cr15_model = CRModel(os.path.join(bert_cr_model, "CR_15"))
cr16_model = CRModel(os.path.join(bert_cr_model, "CR_16"))
cr17_model = CRModel(os.path.join(bert_cr_model, "CR_17"))
cr18_model = CRModel(os.path.join(bert_cr_model, "CR_18"))
cr19_model = CRModel(os.path.join(bert_cr_model, "CR_19"))
cr20_model = CRModel(os.path.join(bert_cr_model, "CR_20"))
cr21_model = CRModel(os.path.join(bert_cr_model, "CR_21"))
cr22_model = CRModel(os.path.join(bert_cr_model, "CR_22"))
cr23_model = CRModel(os.path.join(bert_cr_model, "CR_23"))
cr24_model = CRModel(os.path.join(bert_cr_model, "CR_24"))
cr25_model = CRModel(os.path.join(bert_cr_model, "CR_25"))
cr26_model = CRModel(os.path.join(bert_cr_model, "CR_26"))

# 隐私政策句子分类
def policy_sentences_classification(parsed_sentences):
    for sentence_item in parsed_sentences:
        if sentence_item["privacy_category"] == 'None' or sentence_item["privacy_category"] is None:
            sentence = sentence_item["sentence"]
            pc_predictions, raw_outputs = pc_model.predict([sentence])
            sentence_item["privacy_category"] = str(pc_predictions[0])
    for sentence_item in parsed_sentences:
        sentence = sentence_item["sentence"]
        sentence_item["compliance_rules"] = []
        if sentence_item["privacy_category"] == "1":
            cr1_predictions = cr1_model.predict(sentence)
            if cr1_predictions:
                sentence_item["compliance_rules"].append("1")
            cr2_predictions = cr2_model.predict(sentence)
            if cr2_predictions:
                sentence_item["compliance_rules"].append("2")
        elif sentence_item["privacy_category"] == "2":
            cr3_predictions = cr3_model.predict(sentence)
            if cr3_predictions:
                sentence_item["compliance_rules"].append("3")
            cr4_predictions = cr4_model.predict(sentence)
            if cr4_predictions:
                sentence_item["compliance_rules"].append("4")
        elif sentence_item["privacy_category"] == "3":
            cr5_predictions = cr5_model.predict(sentence)
            if cr5_predictions:
                sentence_item["compliance_rules"].append("5")
        elif sentence_item["privacy_category"] == "4":
            cr6_predictions = cr6_model.predict(sentence)
            if cr6_predictions:
                sentence_item["compliance_rules"].append("6")
            cr7_predictions = cr7_model.predict(sentence)
            if cr7_predictions:
                sentence_item["compliance_rules"].append("7")
            cr8_predictions = cr8_model.predict(sentence)
            if cr8_predictions:
                sentence_item["compliance_rules"].append("8")
            cr9_predictions = cr9_model.predict(sentence)
            if cr9_predictions:
                sentence_item["compliance_rules"].append("9")
            cr10_predictions = cr10_model.predict(sentence)
            if cr10_predictions:
                sentence_item["compliance_rules"].append("10")
        elif sentence_item["privacy_category"] == "5":
            cr11_predictions = cr11_model.predict(sentence)
            if cr11_predictions:
                sentence_item["compliance_rules"].append("11")
            cr12_predictions = cr12_model.predict(sentence)
            if cr12_predictions:
                sentence_item["compliance_rules"].append("12")
            cr13_predictions = cr13_model.predict(sentence)
            if cr13_predictions:
                sentence_item["compliance_rules"].append("13")
            cr14_predictions = cr14_model.predict(sentence)
            if cr14_predictions:
                sentence_item["compliance_rules"].append("14")
            cr15_predictions = cr15_model.predict(sentence)
            if cr15_predictions:
                sentence_item["compliance_rules"].append("15")
            cr16_predictions = cr16_model.predict(sentence)
            if cr16_predictions:
                sentence_item["compliance_rules"].append("16")
            cr17_predictions = cr17_model.predict(sentence)
            if cr17_predictions:
                sentence_item["compliance_rules"].append("17")
        elif sentence_item["privacy_category"] == "6":
            cr18_predictions = cr18_model.predict(sentence)
            if cr18_predictions:
                sentence_item["compliance_rules"].append("18")
            cr19_predictions = cr19_model.predict(sentence)
            if cr19_predictions:
                sentence_item["compliance_rules"].append("19")
            cr20_predictions = cr20_model.predict(sentence)
            if cr20_predictions:
                sentence_item["compliance_rules"].append("20")
            cr21_predictions = cr21_model.predict(sentence)
            if cr21_predictions:
                sentence_item["compliance_rules"].append("21")
            cr22_predictions = cr22_model.predict(sentence)
            if cr22_predictions:
                sentence_item["compliance_rules"].append("22")
        elif sentence_item["privacy_category"] == "7":
            cr23_predictions = cr23_model.predict(sentence)
            if cr23_predictions:
                sentence_item["compliance_rules"].append("23")
            cr24_predictions = cr24_model.predict(sentence)
            if cr24_predictions:
                sentence_item["compliance_rules"].append("24")
            cr25_predictions = cr25_model.predict(sentence)
            if cr25_predictions:
                sentence_item["compliance_rules"].append("25")
            cr26_predictions = cr26_model.predict(sentence)
            if cr26_predictions:
                sentence_item["compliance_rules"].append("26")
    return parsed_sentences