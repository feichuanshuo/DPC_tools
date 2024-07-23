import os
from stable_baselines3.sac.policies import MlpPolicy
from stable_baselines3 import SAC
from utils.automator.algorithms.ExplorationAlgorithm import ExplorationAlgorithm
from utils.automator.algorithms.utils.TimerCallback import TimerCallback
from utils.automator.algorithms.utils.wrapper import TimeFeatureWrapper


class SACAlgorithm(ExplorationAlgorithm):

    @staticmethod
    def explore(app, timesteps, timer, save_policy=False, reload_policy=False,
                policy_dir='.', cycle=0, train_freq=5, target_update_interval=10, **kwargs):
        try:
            app_name = app.package.split('.')[-1]
            # env = TimeFeatureWrapper(app)
            env = app
            # Loading a previous policy and checking file existence
            if reload_policy and (os.path.isfile(f'{policy_dir}{os.sep}{app_name}.zip')):
                temp_dim = env.action_space.high[0]
                env.action_space.high[0] = env.env.ACTION_SPACE
                print(f'Reloading Policy {app_name}.zip')
                model = SAC.load(f'{policy_dir}{os.sep}{app_name}', env)
                env.action_space.high[0] = temp_dim
            else:
                print('Starting training from zero')
                model = SAC(MlpPolicy, env, verbose=1, train_freq=train_freq, target_update_interval=target_update_interval, device='cuda')
            # model.env.envs[0].check_activity()
            m
            callback = TimerCallback(timer=timer, app=app)
            model.learn(total_timesteps=timesteps, callback=callback)
            # It will overwrite the previous policy
            if save_policy:
                print('Saving Policy...')
                model.action_space.high[0] = model.env.envs[0].ACTION_SPACE
                model.save(f'{policy_dir}{os.sep}{app_name}')
            return True
        except Exception as e:
            print(e)
            return False

