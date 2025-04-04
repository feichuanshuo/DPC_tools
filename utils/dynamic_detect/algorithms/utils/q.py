import numpy as np
import texttable as tt
import pickle
from loguru import logger


# 1. Load Environment and Q-table structure
class Q:
    def __init__(self, env, timer, strategy='eps-greedy', eps=0.6):
        self.table_abstraction = {}
        self.tab = tt.Texttable()
        self.timer = timer
        self.env = env
        self.alfa = .628
        self.gamma = .9
        if strategy == 'eps-greedy':
            self.eps = eps
            headlines = ['Q-learning', 'Ɛ-Greedy Strategy', 'epsilon', 'alfa', 'gamma']
            self.tab.header(headlines)
            self.tab.add_row(['', 'True', self.eps, self.alfa, self.gamma])
            print(self.tab.draw())

    # Q-learning Algorithm
    def learn(self, timesteps):
        # Reset environment
        done = False
        j = 0
        old_obs = self.env.reset()
        self.update_table(old_obs)
        # The Q-Table learning algorithm
        while (j < timesteps) and (not self.timer.timer_expired()):
            j += 1
            # Choose action from Q table
            # generate a random number
            greedy = np.random.uniform(0, 1)
            if greedy < self.eps:
                a = self.env.action_space.sample()
                logger.debug(f'random action: {a}')
            # greedy else ->
            else:
                a = self.ret_argmax_q_value(old_obs)
                logger.debug(f'q-learn action: {a}')
            # Get new state & reward from environment
            obs, reward, done, _ = self.env.step(a)
            logger.debug(f'observation: {obs}, reward: {reward}, done: {done}')
            # Update Q-Table with new knowledge
            self.update_table(obs)
            q_value = self.ret_q_value(old_obs, a) + self.alfa * (reward + self.gamma * self.ret_max_q_value(obs) -
                                                                  self.ret_q_value(old_obs, a))
            self.update_table(old_obs, a, q_value)
            old_obs = obs
            if done:
                old_obs = self.env.reset()

    def update_table(self, obs, action=None, value=None):
        bytes_obs = obs.tobytes()
        if bytes_obs not in self.table_abstraction.keys():
            activities = self.env.ACTION_SPACE + 1
            bool_action = 2
            self.table_abstraction.update({bytes_obs: np.zeros([activities, bool_action])})
        elif (action is not None) and (value is not None):
            self.table_abstraction[bytes_obs][action[0]][action[1]] = value
        else:
            pass

    def ret_q_value(self, obs, action):
        return self.table_abstraction[obs.tobytes()][action[0]][action[1]]

    def ret_argmax_q_value(self, obs):
        return np.array(list(np.unravel_index(np.argmax(self.table_abstraction[obs.tobytes()], axis=None),
                                              self.table_abstraction[obs.tobytes()].shape)))

    def ret_max_q_value(self, obs):
        position = np.array(list(np.unravel_index(np.argmax(self.table_abstraction[obs.tobytes()], axis=None),
                                                  self.table_abstraction[obs.tobytes()].shape)))
        return self.ret_q_value(obs, position)

    def save_q_table(self, filename='q_table.pkl'):
        """
        保存Q表格参数
        """
        with open(filename, 'wb') as f:
            pickle.dump(self.table_abstraction, f)
        print(f'Q-table saved to {filename}')

    def load_q_table(self, filename='q_table.pkl'):
        """
        加载Q表格参数
        """
        with open(filename, 'rb') as f:
            self.table_abstraction = pickle.load(f)
        print(f'Q-table loaded from {filename}')