# Copyright 2022 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import logging
from threading import Thread, Lock, Event
import time

from casbin.model import Model
from redis.client import Redis, PubSub
from redis.backoff import ExponentialBackoff
from redis.retry import Retry as RedisRetry


from casbin_redis_watcher.options import WatcherOptions


class RedisWatcher:
    def __init__(self, logger=None):
        self.mutex: Lock = Lock()
        self.sub_client: PubSub = None
        self.pub_client: Redis = None
        self.options: WatcherOptions = None
        self.close = None
        self.sleep = 0
        self.execute_update = False
        self.callback: callable = None
        self.subscribe_thread: Thread = Thread(target=self.subscribe, daemon=True)
        self.subscribe_event = Event()

        self.logger = logger if logger else logging.getLogger(__name__)

    def recreate_thread(self):
        self.sleep = 10
        self.execute_update = True
        self.subscribe_thread: Thread = Thread(target=self.subscribe,
                                               daemon=True
                                               )
        self.subscribe_event = Event()
        self.close = False
        self.subscribe_thread.start()
        self.subscribe_event.wait(timeout=1)

    def init_config(self, option: WatcherOptions):
        if option.optional_update_callback:
            self.set_update_callback(option.optional_update_callback)
        else:
            self.logger.warning("No callback function is set.Use the default callback function.")
            self.callback = self.default_callback_func

        self.options = option

    def set_update_callback(self, callback: callable):
        with self.mutex:
            self.callback = callback

    def _get_redis_conn(self):
        """
        Creates a new redis connection instance
        """
        rds = Redis(host=self.options.host, port=self.options.port,
                    password=self.options.password,
                    ssl=self.options.ssl,
                    retry=RedisRetry(ExponentialBackoff(), 3)
                    )
        return rds

    def init_publisher_subscriber(self, init_pub=True, init_sub=True):
        """
        Initialize the publisher and subscriber subscribers
        NOTE: A new Redis connection is created for the publisher and subscriber because since Redis5
              the connection needs to be created by thread
        Args:
            init_pub (bool, optional): Whether to initialize the publisher subscriber. Defaults to True.
            init_sub (bool, optional): Whether to initialize the publisher subscriber. Defaults to True.
        """
        try:
            if init_pub:
                rds = self._get_redis_conn()
                if not rds.ping():
                    raise Exception("Redis not responding.")
                self.pub_client = rds.client()

            if init_sub:
                rds = self._get_redis_conn()
                if not rds.ping():
                    raise Exception("Redis not responding.")
                self.sub_client = rds.client().pubsub()
        except Exception as e:
            if self.pub_client:
                self.pub_client.close()
            if self.sub_client:
                self.sub_client.close()
            self.pub_client = None
            self.sub_client = None
            print(f"Casbin Redis Watcher error: {e}. Publisher/Subscriber failed to be initialized {self.options.local_ID}")

    def update(self):
        def func():
            with self.mutex:
                msg = MSG("Update", self.options.local_ID, "", "", "")
                return self.pub_client.publish(self.options.channel, msg.marshal_binary())

        return self.log_record(func)

    def update_for_add_policy(self, sec: str, ptype: str, *params: str):
        def func():
            with self.mutex:
                msg = MSG("UpdateForAddPolicy", self.options.local_ID, sec, ptype, params)
                return self.pub_client.publish(self.options.channel, msg.marshal_binary())

        return self.log_record(func)

    def update_for_remove_policy(self, sec: str, ptype: str, *params: str):
        def func():
            with self.mutex:
                msg = MSG("UpdateForRemovePolicy", self.options.local_ID, sec, ptype, params)
                return self.pub_client.publish(self.options.channel, msg.marshal_binary())

        return self.log_record(func)

    def update_for_remove_filtered_policy(self, sec: str, ptype: str, field_index: int, *params: str):
        def func():
            with self.mutex:
                msg = MSG(
                    "UpdateForRemoveFilteredPolicy",
                    self.options.local_ID,
                    sec,
                    ptype,
                    f"{field_index} {' '.join(params)}",
                )
                return self.pub_client.publish(self.options.channel, msg.marshal_binary())

        return self.log_record(func)

    def update_for_save_policy(self, model: Model):
        def func():
            with self.mutex:
                msg = MSG(
                    "UpdateForSavePolicy",
                    self.options.local_ID,
                    "",
                    "",
                    model.to_text(),
                )
                return self.pub_client.publish(self.options.channel, msg.marshal_binary())

        return self.log_record(func)

    @staticmethod
    def default_callback_func(msg: str):
        print("callback: " + msg)

    def log_record(self, f: callable):
        try:
            if not self.pub_client:
                rds = self._get_redis_conn()
                self.pub_client = rds.client()
            result = f()
        except Exception as e:
            if self.pub_client:
                self.pub_client.close()
            print(f"Casbin Redis Watcher error: {e}. Publisher failure on the worker {self.options.local_ID}")
        else:
            return result

    @staticmethod
    def unsubscribe(psc: PubSub):
        return psc.unsubscribe()

    def subscribe(self):
        time.sleep(self.sleep)
        try:
            if not self.sub_client:
                rds = self._get_redis_conn()
                self.sub_client = rds.client().pubsub()
            self.sub_client.subscribe(self.options.channel)
            print(f"Waiting for casbin updates... in the worker: {self.options.local_ID}")
            if self.execute_update:
                self.update()
            try:
                for item in self.sub_client.listen():
                    if not self.subscribe_event.is_set():
                        self.subscribe_event.set()
                    if item is not None and item["type"] == "message":
                        try:
                            with self.mutex:
                                self.callback(str(item))
                        except Exception as listen_exc:
                            print("Casbin Redis watcher failed sending update to teh callback function "
                                  " process due to: {}".format(str(listen_exc)))
                            if self.sub_client:
                                self.sub_client.close()
                            break
            except Exception as sub_exc:
                print("Casbin Redis watcher failed to get message from redis due to {}".format(str(sub_exc)))
                if self.sub_client:
                    self.sub_client.close()
        except Exception as redis_exc:
            print("Casbin Redis watcher failed to subscribe due to: {}"
                  .format(str(redis_exc)))
        finally:
            if self.sub_client:
                self.sub_client.close()

    def should_reload(self, recreate=True):
        """
        Checks is the thread and event are still alive, if they are not they are recreated.
        If they were recreated the watcher should reload the policies.
        Args:
            recreate(bool): recreates the thread if it's dead for redis timeouts
        """
        try:
            if self.subscribe_thread.is_alive() and self.subscribe_event.is_set():
                return False
            else:
                if recreate and not self.subscribe_thread.is_alive():
                    print(f"Casbin Redis Watcher will be recreated for the worker {self.options.local_ID} in 10 secs.")
                    self.recreate_thread()
                return True
        except Exception:
            return True

    def update_callback(self):
        """
        This method was created to cover the function that flask_authz calls
        """
        self.update()


class MSG:
    def __init__(self, method="", ID="", sec="", ptype="", *params):
        self.method: str = method
        self.ID: str = ID
        self.sec: str = sec
        self.ptype: str = ptype
        self.params = params

    def marshal_binary(self):
        return json.dumps(self.__dict__)

    @staticmethod
    def unmarshal_binary(data: bytes):
        loaded = json.loads(data)
        loaded.pop("params", None)
        return MSG(**loaded)


def new_watcher(option: WatcherOptions, logger=None):
    option.init_config()
    w = RedisWatcher(logger)
    w.init_config(option)
    w.init_publisher_subscriber()
    w.close = False
    w.subscribe_thread.start()
    w.subscribe_event.wait(timeout=5)
    return w


def new_publish_watcher(option: WatcherOptions):
    option.init_config()
    w = RedisWatcher()
    w.init_config(option)
    w.init_publisher_subscriber(init_sub=False)
    w.close = False
    return w
