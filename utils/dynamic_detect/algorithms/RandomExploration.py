import traceback

from utils.dynamic_detect.algorithms.ExplorationAlgorithm import ExplorationAlgorithm
from utils.dynamic_detect.algorithms import Timer
from loguru import logger


class RandomAlgorithm(ExplorationAlgorithm):

    @staticmethod
    def explore(env, timesteps, timer, **kwargs):
        """
        随机探索算法
        :param env: 强换学习的交互环境
        :param timesteps: 每回合的时间步数
        :param timer: 总的测试时间
        :param kwargs:
        :return:
        """
        try:
            env.reset()
            t = Timer(timer)
            while not t.timer_expired():
                action = env.action_space.sample()
                observation, reward, done, _ = env.step(action)
                logger.debug(f'observation: {observation}, reward: {reward}, done: {done}')
                if done:
                    env.reset()
            return True
        except Exception as e:
            logger.error(f'Error: {e}')
            logger.error(f'Stack trace:, {traceback.format_exc()}')
            return False
