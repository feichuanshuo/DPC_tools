from utils.automator.algorithms.ExplorationAlgorithm import ExplorationAlgorithm
from utils.automator.algorithms import Timer


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
                o, _, done, _ = env.step(action)
                print("o: ", o)
                # 记录代码覆盖率
                # env.coverage_count += 1
                # if (env.timesteps % 25) == 0 and env.instr:
                #     env.instr_funct(udid=env.udid, package=env.package, coverage_dir=env.coverage_dir,
                #                     coverage_count=env.coverage_count)
                if done:
                    env.reset()
            return True
        except Exception:
            return False
