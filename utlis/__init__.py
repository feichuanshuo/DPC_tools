import time


def now():
    """ 获取当前时间 """

    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))

def print_msg(msg):
    """格式化输出

    :param msg: 文本
    :return:
    """

    print("[*] {now} {msg}".format(now=now(), msg=str(msg)))


def dalvik_to_java_type(dalvik_type):
    """将 Dalvik 字节码类型转换为 Java 类型"""
    basic_types = {
        'Z': 'boolean',
        'B': 'byte',
        'S': 'short',
        'C': 'char',
        'I': 'int',
        'J': 'long',
        'F': 'float',
        'D': 'double',
        'V': 'void'
    }

    if dalvik_type.startswith('L') and dalvik_type.endswith(';'):
        # 对象类型
        return dalvik_type[1:-1].replace('/', '.')
    elif dalvik_type.startswith('['):
        # 数组类型
        depth = 0
        while dalvik_type[depth] == '[':
            depth += 1
        base_type = dalvik_to_java_type(dalvik_type[depth:])
        return base_type + '[]' * depth
    else:
        # 基本类型
        return basic_types.get(dalvik_type, dalvik_type)