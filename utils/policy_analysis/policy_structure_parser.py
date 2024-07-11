import os.path
import re
from xml.etree import ElementTree
import xml.dom.minidom
import pandas as pd
from resources.configuration import paragraph_number_regex_path, paragraph_numbers_path
from utils.common.similarity_calculation import judge_privacy_category


class policy_structure_parser:
    def __init__(self, target_file_path):
        self.target_file_path = target_file_path

        # 段落编号正则表达式
        self.paragraph_number_regex_path = paragraph_number_regex_path
        self.paragraph_number_regex = self.get_paragraph_number_regex()

        # 段落编号
        self.paragraph_numbers_path = paragraph_numbers_path
        self.paragraph_numbers, self.start_paragraph_numbers = self.get_paragraph_numbers()

        self.sentences = self.read_privacy_policy()
        self.parsed_sentences = []
        self.parsed_sentences_with_PC = []

        self.special_pn_type = [23, 24, 25]

        self.able_to_have_next = []

        self.root = None  # XML root node
        self.parse_error_info = None
        self.get_formatted_xml_error_info = None
        self.formatted_xml_string = None
        self.node_list = {}
        self.flag_has_catalog = 0
        self.sentences_pn = []
        self.sentences_node = []

    # 从资源中读取正则表达式以提取段落编号
    def get_paragraph_number_regex(self):
        """
        Read the regular expressions from resources to extract the paragraph numbers
        """
        regex_df = pd.read_csv(self.paragraph_number_regex_path, sep='\t')

        return list(regex_df['expressions'])

    # 从资源中读取段落编号
    def get_paragraph_numbers(self):
        """
        Read paragraph numbers from resources
        """
        paragraph_numbers = {}
        start_paragraph_numbers = []

        with open(self.paragraph_numbers_path, 'r', encoding='utf-8') as f:
            paragraphNumbers_data = f.readlines()
        for m_index, m in enumerate(paragraphNumbers_data):
            new_m = m.rstrip('\n')
            paragraph_numbers[m_index] = new_m.split(';')

        for k, v in paragraph_numbers.items():
            start_paragraph_numbers.append(v[0])

        return paragraph_numbers, start_paragraph_numbers

    # 阅读、清理和规范化隐私政策文本
    def read_privacy_policy(self):
        """
        Read, clean and normalize privacy policy text
        :return: A list of sentences (which are cleaned and normalized) in the privacy policy
        """
        sentences = []

        with open(self.target_file_path, 'r', encoding='utf-8') as f:
            texts = f.read()

        # 将Unicode字符\xa0（非断行空格）替换为普通空格。
        texts = texts.replace(u'\xa0', ' ')
        # 将中文句号'．'替换为英文句号'.'
        texts = texts.replace('．', '.')
        # 按照换行符\n将文本分割成列表，每个元素是一行。
        texts = texts.split('\n')
        # 去除列表中每个字符串元素的首尾空白字符
        texts = [t.strip() for t in texts]
        # 过滤掉列表中的空字符串
        texts = [t for t in texts if t != '']

        # "3 How to contact us", -> "3. How to contact us"
        regex = '\d{1,2} '
        pattern = re.compile(regex)
        for index, text in enumerate(texts):
            match_result = pattern.match(text)
            if match_result is not None:
                temp_index = match_result.end()
                text_list = list(text)
                text_list[temp_index - 1] = '.'
                texts[index] = ''.join(text_list)

        # "1.1.1." -> "1.1.1"
        regexes = ['(\d{1,2}\.\d{1,2}\.\d{1,2}\.)[^\d]', '(\d{1,2}\.\d{1,2}\.)[^\d]']
        for index, text in enumerate(texts):
            for regex in regexes:
                pattern = re.compile(regex)
                matched = pattern.match(text + ' ')
                if matched is not None:
                    matched_text = matched.group(1)
                    matched_length = len(matched_text)
                    temp_text = texts[index][matched_length:].lstrip('.')
                    texts[index] = matched_text[:-1] + ' ' + temp_text

        # texts = [t.replace(' ', '') for t in texts] # For Chinese policies, here we remove the spaces from texts

        # "1. \n xxx" -> "1. xxx"
        alone_pn_index = []

        for index, text in enumerate(texts):
            for regex in self.paragraph_number_regex:
                pattern = re.compile(regex)
                paragraphNumber = pattern.match(text + ' ')
                if paragraphNumber is not None:
                    pn_length = len(paragraphNumber.group(1))
                    if len(text) == pn_length:
                        alone_pn_index.append(index)

        for index in alone_pn_index:
            texts[index] += texts[index + 1]

        alone_pn_index_delete = [i + 1 for i in alone_pn_index]
        texts = [texts[i] for i in range(len(texts)) if i not in alone_pn_index_delete]

        for text in texts:
            # split text with periods
            for split_text in text.split('。'):
                # split text with colons
                if '：' in split_text or ':' in split_text:
                    t1 = re.split('[：:]', split_text)
                    for index, t2 in enumerate(t1):
                        flag = 0
                        for regex in self.paragraph_number_regex:
                            pattern = re.compile(regex)
                            paragraphNumber = pattern.match(t2)
                            if paragraphNumber is not None:
                                sentences.append(t2)
                                flag = 1
                                break
                        if not flag:
                            if index == 0:
                                sentences.append(t2)
                            else:
                                if '：' in split_text:
                                    sentences[-1] += '：' + t2
                                elif ':' in split_text:
                                    sentences[-1] += ':' + t2
                else:
                    sentences.append(split_text)

        # clean sentences twice
        for times in range(2):
            sentences = [s.strip() for s in sentences]
            sentences = [s for s in sentences if s != '']
            # sentences = [s.replace(' ', '') for s in sentences] # For Chinese policies, here we remove the spaces from texts
            sentences = [s.strip('.') for s in sentences]
            sentences = [s.strip() for s in sentences]
            sentences = [s for s in sentences if s != '']
            sentences = [s.strip('*') for s in sentences]
            sentences = [s.strip() for s in sentences]
            sentences = [s for s in sentences if s != '']

        return sentences

    # 判断段落编号的类型
    def judge_pn_type(self, targetPN):
        """
        Obtain the type of paragraph number
        :param targetPN: target paragraph number
        """
        targetPN += ' '

        PNType = []
        for index, regex in enumerate(self.paragraph_number_regex):
            pattern = re.compile(regex)
            paragraphNumber = pattern.match(targetPN)
            if paragraphNumber is not None:
                PNType.append(index + 1)

        if not PNType:
            return None

        return PNType[0]

    # 判断段落编号是否为起始段落编号
    def is_start(self, targetPN, PNType):
        """
        Determine whether the target paragraph number is the starting paragraph number
        """
        if targetPN in self.start_paragraph_numbers:
            return True

        if PNType in self.special_pn_type:
            lastNumber = int(targetPN.split('.')[-1])
            if lastNumber == 1:
                return True
        else:
            return False

    # 判断段落编号是否为起始段落编号（不考虑段落编号类型）
    def is_start_without_pn_type(self, targetPN):
        if targetPN is None:
            return False

        PNType = self.judge_pn_type(targetPN)

        return self.is_start(targetPN, PNType)

    # 判断段落编号2是否为段落编号1的前一个段落编号
    def is_previous(self, paragraphNumber1, paragraphNumber2):
        """
        Determine whether paragraphNumber2 is the previous paragraph number of the paragraphNumber1.
        For example, paragraphNumber1 = '2.', paragraphNumber2 = '1.' -> True
        """
        if paragraphNumber1 is None or paragraphNumber2 is None:
            return False

        PNType1 = self.judge_pn_type(paragraphNumber1)
        PNType2 = self.judge_pn_type(paragraphNumber2)

        if PNType1 != PNType2:
            return False
        else:
            if PNType1 in self.special_pn_type:
                if not (paragraphNumber1.split('.')[:-1] == paragraphNumber2.split('.')[:-1]):
                    return False

                lastNumber1 = int(paragraphNumber1.split('.')[-1])
                lastNumber2 = int(paragraphNumber2.split('.')[-1])
                if lastNumber2 == lastNumber1 - 1:
                    return True
                else:
                    return False
            else:
                index1 = self.paragraph_numbers[PNType1 - 1].index(paragraphNumber1)
                index2 = self.paragraph_numbers[PNType2 - 1].index(paragraphNumber2)
                if index1 == index2 + 1:
                    return True
                else:
                    return False

    # 查找前一个段落编号
    def find_previous(self, paragraphNumberList, targetIndex):
        """
        Find the previous paragraph number, and return the index of it
        """
        tempList = paragraphNumberList[:targetIndex]
        tempList.reverse()
        for index, ll in enumerate(tempList):
            # fixme: 判断条件可能有误
            if ll == paragraphNumberList:
                return None
            if self.is_previous(paragraphNumberList[targetIndex], ll) and self.able_to_have_next[
                targetIndex - 1 - index] == 1:
                lastIndex = targetIndex - 1 - index
                return lastIndex

        return None

    # 构建xml树
    def get_xml_root(self, targetPNList):
        """
        Get the XML root node
        """
        parents = {}
        for i in range(len(targetPNList)):
            self.able_to_have_next.append(1)

        self.root = ElementTree.Element('PrivacyPolicy')

        for index, targetPN in enumerate(targetPNList):
            if index == 0:
                parents[index] = self.root
                nowNode = ElementTree.SubElement(parents[index], 'PolicyTexts', attrib={'pn': targetPN})
                self.node_list[index] = nowNode

            elif self.is_start_without_pn_type(targetPN):
                parents[index] = self.node_list[index - 1]
                nowNode = ElementTree.SubElement(parents[index], 'PolicyTexts', attrib={'pn': targetPN})
                self.node_list[index] = nowNode

            else:
                lastIndex = self.find_previous(targetPNList, index)
                if lastIndex is None:
                    self.parse_error_info = 'Fail to find the previous paragraph number of {}-{}'.format(index,
                                                                                                         targetPNList[
                                                                                                             index])
                    return 0

                for i in range(lastIndex, index):
                    self.able_to_have_next[i] = 0

                parents[index] = parents[lastIndex]
                nowNode = ElementTree.SubElement(parents[index], 'PolicyTexts', attrib={'pn': targetPN})
                self.node_list[index] = nowNode

        return 1

    def parse_privacy_policy(self):
        """
        Parse the privacy policy
        """
        # 将每个句子的段落编号提取出来，存在则存储，不存在则存储为None
        for sentence in self.sentences:
            flagStartedWithPN = 0

            for index, regex in enumerate(self.paragraph_number_regex):
                pattern = re.compile(regex)
                paragraphNumber = pattern.match(sentence)
                if paragraphNumber is not None:
                    flagStartedWithPN = 1
                    self.sentences_pn.append(paragraphNumber.group(1))
                    break
            if not flagStartedWithPN:
                self.sentences_pn.append(None)

        # For Chinese policies, here we remove the catalog paragraph number
        # 对于中文，移除目录段落编号
        for times in range(3):
            for i in range(len(self.sentences_pn)):
                if self.sentences_pn[i] is None:
                    continue

                if (self.is_start_without_pn_type(self.sentences_pn[i]) and
                        self.is_previous(self.sentences_pn[i + 1], self.sentences_pn[i]) and
                        self.is_previous(self.sentences_pn[i + 2], self.sentences_pn[i + 1]) and
                        self.is_previous(self.sentences_pn[i + 3], self.sentences_pn[i + 2])):
                    self.flag_has_catalog = 1
                    self.sentences_pn[i] = None

                    for j in range(i + 1, len(self.sentences_pn)):
                        if self.is_start_without_pn_type(self.sentences_pn[j]):
                            break
                        self.sentences_pn[j] = None
                    break
                else:
                    break

        # 将句子段落编号中的中文括号、逗号替换为英文括号、句号，并将句子转换为小写
        tempPNList = [m for m in self.sentences_pn if m is not None]
        tempPNList = [m.replace('（', '(') for m in tempPNList]
        tempPNList = [m.replace('）', ')') for m in tempPNList]
        tempPNList = [m.replace('、', '.') for m in tempPNList]
        tempPNList = [m.lower() for m in tempPNList]

        flag = self.get_xml_root(tempPNList)

        if not flag:
            for sentence in self.sentences:
                temp = {'sentence': sentence, 'privacy_category': None}
                self.parsed_sentences_with_PC.append(temp)
            return 0

        num = 0
        for PN in self.sentences_pn:
            if PN is None:
                self.sentences_node.append(None)
            else:
                self.sentences_node.append(self.node_list[num])
                num = num + 1

        # Populate privacy policy text into the XML tree
        # 将隐私政策文本填充到XML树中
        for index, sentence in enumerate(self.sentences):
            if index == 0:
                self.root.text = sentence
                continue

            node = self.sentences_node[index]
            if node is not None:
                if node.text is None:
                    node.text = sentence
                else:
                    node.text = node.text + '。' + sentence
            else:
                tempSentenceNode = self.sentences_node[:index]
                tempSentenceNode.reverse()

                n = -1
                for i, t in enumerate(tempSentenceNode):
                    if t is not None:
                        n = i
                        break

                if n == -1:
                    self.root.text = self.root.text + '。' + sentence
                else:
                    node = self.sentences_node[index - 1 - n]
                    if node.text is None:
                        node.text = sentence
                    else:
                        node.text = node.text + '。' + sentence

        self.concatenate_xml(self.root)
        self.set_subtitle_attribute(self.root)
        self.set_subtitle_pc_attribute(self.root)
        # Flag
        self.parse_2_formatted_xml()
        self.get_parsed_sentences(self.root)
        self.get_parsed_sentences_with_PC(self.root)

        return 1

    def parse_2_formatted_xml(self):
        """
        Get formatted XML string
        """
        xmlString = ElementTree.tostring(self.root, encoding='UTF-8')
        try:
            xmls = xml.dom.minidom.parseString(xmlString)
        except Exception as e:
            self.get_formatted_xml_error_info = 'Fail to get formatted XML-{}'.format(e)
            return 0

        self.formatted_xml_string = xmls.toprettyxml()

        return 1

    # 连接XML树
    def concatenate_xml(self, node):
        if node.text is None:
            for child in list(node):
                self.concatenate_xml(child)
        elif node.text.endswith('：'):
            split_text = node.text.split('。')
            if len(split_text) == 1 and node.get('pn') is not None:
                starting_text_PN_length = len(node.get('pn'))
                starting_text = split_text[-1][starting_text_PN_length:]
            else:
                starting_text = split_text[-1]

            for child in list(node):
                PN_length = len(child.get("pn"))
                child_text = child.text
                child.text = child_text[:PN_length] + starting_text + child_text[PN_length:]
            for child in list(node):
                self.concatenate_xml(child)
        else:
            for child in list(node):
                self.concatenate_xml(child)

        return

    # 为XML树设置subtitle属性
    def set_subtitle_attribute(self, node):
        """
        Set subtitle attribute for XML tree
        :param node: node
        :return: None
        """
        pn = node.get('pn')
        text = node.text

        if pn is not None and text is not None:
            node.set('subtitle', node.text[len(pn):].split('。')[0].strip())

        for child in list(node):
            self.set_subtitle_attribute(child)

    def get_parsed_sentences(self, node):
        if node.text is not None:
            self.parsed_sentences.extend(node.text.split('。'))
        for child in list(node):
            self.get_parsed_sentences(child)

    def get_parsed_sentences_with_PC(self, node):
        if node.text is not None:
            sentences = node.text.split('。')
            pc = node.get('pc')
            for sentence in sentences:
                temp = {'sentence': sentence, 'privacy_category': pc}
                self.parsed_sentences_with_PC.append(temp)
        for child in list(node):
            self.get_parsed_sentences_with_PC(child)

    def output_sentences(self, output_path):
        """
        Write the result to file
        """
        if not os.path.exists(os.path.dirname(output_path)):
            os.makedirs(os.path.dirname(output_path))

        # sentences = []
        # if self.parse_error_info is None:

        with open(output_path, 'w', encoding='utf-8') as f:
            if self.parsed_sentences:
                for sentence in self.parsed_sentences:
                    f.write(sentence + '\n')
            else:
                for sentence in self.sentences:
                    f.write(sentence + '\n')

    # 为节点及其所有子节点设置"pc"属性
    def set_subtitle_pc_attribute_helper(self, node, privacy_category):
        if not (node.get('pc') is not None and privacy_category is None):
            node.set('pc', str(privacy_category))
        children_node = list(node)
        if len(children_node) == 0:
            return
        for child in children_node:
            self.set_subtitle_pc_attribute_helper(child, privacy_category)
        return

    # 为节点及其所有子节点设置"pc"属性（表示subtitle的隐私类别）
    def set_subtitle_pc_attribute(self, node):
        """
        Set the "pc" attribute (representing the privacy category of the subtitle) for node and all its child nodes
        """
        if node.get('pn') is not None:
            self.set_subtitle_pc_attribute_helper(node, judge_privacy_category(node.get('subtitle')))
        children_node = list(node)
        if len(children_node) == 0:
            return
        for child in children_node:
            self.set_subtitle_pc_attribute(child)
        return
