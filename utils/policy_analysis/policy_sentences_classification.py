import os
from simpletransformers.classification import ClassificationModel
from resources.configuration import bert_pc_model, bert_cr_model
# 加载模型
pc_model = ClassificationModel('bert', bert_pc_model)
cr1_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_1"))
cr2_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_2"))
cr3_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_3"))
cr4_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_4"))
cr5_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_5"))
cr6_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_6"))
cr7_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_7"))
cr8_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_8"))
cr9_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_9"))
cr10_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_10"))
cr11_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_11"))
cr12_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_12"))
cr13_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_13"))
cr14_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_14"))
cr15_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_15"))
cr16_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_16"))
cr17_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_17"))
cr18_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_18"))
cr19_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_19"))
cr20_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_20"))
cr21_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_21"))
cr22_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_22"))
cr23_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_23"))
cr24_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_24"))
cr25_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_25"))
cr26_model = ClassificationModel('bert', os.path.join(bert_cr_model, "CR_26"))


# 隐私政策句子分类
def policy_sentences_classification(parsed_sentences):
    for sentence_item in parsed_sentences:
        if sentence_item["privacy_category"] is None:
            sentence = sentence_item["sentence"]
            pc_predictions, raw_outputs = pc_model.predict([sentence])
            sentence_item["privacy_category"] = str(pc_predictions[0])
    for sentence_item in parsed_sentences:
        sentence = sentence_item["sentence"]
        sentence_item["compliance_rules"] = []
        if sentence_item["privacy_category"] == "1":
            cr1_predictions, raw_outputs = cr1_model.predict([sentence])
            if cr1_predictions[0]:
                sentence_item["compliance_rules"].append("1")
            cr2_predictions, raw_outputs = cr2_model.predict([sentence])
            if cr2_predictions[0]:
                sentence_item["compliance_rules"].append("2")
        elif sentence_item["privacy_category"] == "2":
            cr3_predictions, raw_outputs = cr3_model.predict([sentence])
            if cr3_predictions[0]:
                sentence_item["compliance_rules"].append("3")
            cr4_predictions, raw_outputs = cr4_model.predict([sentence])
            if cr4_predictions[0]:
                sentence_item["compliance_rules"].append("4")
        elif sentence_item["privacy_category"] == "3":
            cr5_predictions, raw_outputs = cr5_model.predict([sentence])
            if cr5_predictions[0]:
                sentence_item["compliance_rules"].append("5")
        elif sentence_item["privacy_category"] == "4":
            cr6_predictions, raw_outputs = cr6_model.predict([sentence])
            if cr6_predictions[0]:
                sentence_item["compliance_rules"].append("6")
            cr7_predictions, raw_outputs = cr7_model.predict([sentence])
            if cr7_predictions[0]:
                sentence_item["compliance_rules"].append("7")
            cr8_predictions, raw_outputs = cr8_model.predict([sentence])
            if cr8_predictions[0]:
                sentence_item["compliance_rules"].append("8")
            cr9_predictions, raw_outputs = cr9_model.predict([sentence])
            if cr9_predictions[0]:
                sentence_item["compliance_rules"].append("9")
            cr10_predictions, raw_outputs = cr10_model.predict([sentence])
            if cr10_predictions[0]:
                sentence_item["compliance_rules"].append("10")
        elif sentence_item["privacy_category"] == "5":
            cr11_predictions, raw_outputs = cr11_model.predict([sentence])
            if cr11_predictions[0]:
                sentence_item["compliance_rules"].append("11")
            cr12_predictions, raw_outputs = cr12_model.predict([sentence])
            if cr12_predictions[0]:
                sentence_item["compliance_rules"].append("12")
            cr13_predictions, raw_outputs = cr13_model.predict([sentence])
            if cr13_predictions[0]:
                sentence_item["compliance_rules"].append("13")
            cr14_predictions, raw_outputs = cr14_model.predict([sentence])
            if cr14_predictions[0]:
                sentence_item["compliance_rules"].append("14")
            cr15_predictions, raw_outputs = cr15_model.predict([sentence])
            if cr15_predictions[0]:
                sentence_item["compliance_rules"].append("15")
            cr16_predictions, raw_outputs = cr16_model.predict([sentence])
            if cr16_predictions[0]:
                sentence_item["compliance_rules"].append("16")
            cr17_predictions, raw_outputs = cr17_model.predict([sentence])
            if cr17_predictions[0]:
                sentence_item["compliance_rules"].append("17")
        elif sentence_item["privacy_category"] == "6":
            cr18_predictions, raw_outputs = cr18_model.predict([sentence])
            if cr18_predictions[0]:
                sentence_item["compliance_rules"].append("18")
            cr19_predictions, raw_outputs = cr19_model.predict([sentence])
            if cr19_predictions[0]:
                sentence_item["compliance_rules"].append("19")
            cr20_predictions, raw_outputs = cr20_model.predict([sentence])
            if cr20_predictions[0]:
                sentence_item["compliance_rules"].append("20")
            cr21_predictions, raw_outputs = cr21_model.predict([sentence])
            if cr21_predictions[0]:
                sentence_item["compliance_rules"].append("21")
            cr22_predictions, raw_outputs = cr22_model.predict([sentence])
            if cr22_predictions[0]:
                sentence_item["compliance_rules"].append("22")
        elif sentence_item["privacy_category"] == "7":
            cr23_predictions, raw_outputs = cr23_model.predict([sentence])
            if cr23_predictions[0]:
                sentence_item["compliance_rules"].append("23")
            cr24_predictions, raw_outputs = cr24_model.predict([sentence])
            if cr24_predictions[0]:
                sentence_item["compliance_rules"].append("24")
            cr25_predictions, raw_outputs = cr25_model.predict([sentence])
            if cr25_predictions[0]:
                sentence_item["compliance_rules"].append("25")
            cr26_predictions, raw_outputs = cr26_model.predict([sentence])
            if cr26_predictions[0]:
                sentence_item["compliance_rules"].append("26")
    return parsed_sentences