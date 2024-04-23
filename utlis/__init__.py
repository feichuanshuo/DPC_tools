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