import string

import hanlp
import jieba

from configuration import stopwords_path,pi_extraction_model
import torch
from transformers import  BertForTokenClassification, BertTokenizer

def get_stopwords() -> list:
    """
    Get the stopwords list
    """
    with open(stopwords_path, 'r', encoding='utf-8') as f:
        stopwords = f.read()
    stopwords = stopwords.split("\n")
    return stopwords


def seg_by_jieba(sentence, lower=True, remove_stopwords=False) -> list:
    """
    jieba segmentation for model training (without removing stopwords)
    :param sentence: target sentence
    """
    stopwords = get_stopwords()

    if lower:
        sentence = sentence.lower()

    tokens = jieba.cut(sentence)
    words = []
    for i in tokens:
        if remove_stopwords:
            if i not in stopwords and i != ' ' and i != '\t' and i != '\xa0':
                words.append(i)
        else:
            words.append(i)
    return words


def get_seg_hanlp():
    """
    分词
    """
    seg_hanlp = hanlp.load(hanlp.pretrained.tok.COARSE_ELECTRA_SMALL_ZH)
    return seg_hanlp

def get_pos_hanlp():
    """
    词性标注
    """
    pos_hanlp = hanlp.load(hanlp.pretrained.pos.CTB9_POS_ELECTRA_SMALL)
    return pos_hanlp

def get_punctuatio():
    """
    标点符号
    """
    # 定义标点符号集合
    punctuation = set(string.punctuation + "，。、；：‘’“”（）《》【】")
    return punctuation

# 个人信息提取模型
class PI_Extraction_Model:
    def __init__(self):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.tokenizer = BertTokenizer.from_pretrained(pi_extraction_model)
        self.model =  BertForTokenClassification.from_pretrained(pi_extraction_model).to(self.device)
        self.model.eval()
        self.label_map = {"O": 0, "B": 1, "I": 3, "E": 2}

    def extract_entities(self,sentence,labels):
        """
            从 BIOE 标签中提取实体。

            参数：
                sentence (str): 输入的句子。
                labels (list): 对应的 BIOE 标签序列。
                label_map (dict): 标签到索引的映射，如 {O:0, B:1, I:3, E:2}。

            返回：
                entities (list): 提取的实体列表。
            """
        entities = []
        current_entity = []
        label_to_name = {v: k for k, v in self.label_map.items()}  # 索引到标签的反向映射

        for i, (char, label) in enumerate(zip(sentence, labels)):
            label_name = label_to_name[label]

            if label_name == "B":  # 开始一个新的实体
                if current_entity:  # 如果之前有未完成的实体，先保存
                    entities.append("".join(current_entity))
                    current_entity = []
                current_entity.append(char)
            elif label_name == "I":  # 继续当前实体
                if current_entity:
                    current_entity.append(char)
            elif label_name == "E":  # 结束当前实体
                if current_entity:
                    current_entity.append(char)
                    entities.append("".join(current_entity))
                    current_entity = []
            else:  # O (非实体部分)
                if current_entity:  # 如果之前有未完成的实体，先保存
                    entities.append("".join(current_entity))
                    current_entity = []

        # 检查是否有未完成的实体
        if current_entity:
            entities.append("".join(current_entity))

        return entities


    def predict(self, sentence):
        inputs = self.tokenizer(sentence, return_tensors='pt', padding=True, truncation=True, max_length=512)
        input_ids = inputs["input_ids"].to(self.device)
        attention_mask = inputs["attention_mask"].to(self.device)

        # 执行预测
        with torch.no_grad():
            outputs = self.model(input_ids, attention_mask=attention_mask)
            logits = outputs.logits  # 获取模型输出的 logits
            predictions = torch.argmax(logits, dim=-1)  # 获取预测标签
        # 将预测结果转换为列表
        predicted_labels = predictions.cpu().numpy().flatten()
        res = self.extract_entities(sentence,predicted_labels)
        # for i in range(len(sentence)):
        #     print(sentence[i],predicted_labels[i])
        return res