import time
import contextlib
import threading
import hashlib
import json
import inspect

from decouple import config
from errbot import BotPlugin
from errbot import botcmd
from errbot import arg_botcmd
from errbot import cmdfilter
from errbot.backends.base import Message as ErrbotMessage
from errbot.backends.base import Person
from typing import Dict
from typing import Tuple
from typing import Union

class Duo2fa(BotPlugin):
    """
    This implements duo 2fa as a cmdfilter for other plugin commands
    """
    # Plugin Setup Methods
    def activate(self)->None:
        """
        Activate activates our plugin and sets up some things it needs

        Returns:
            None
        """
        super().activate()
        if 'cmds' not in self:
            self['cmds'] = set()
        if 'lock' not in self:
            self.lock = threading.Lock()

    def configure(self, configuration: Dict)->None:
        """
        Configure gathers configuration from the user or from the environment and configures the plugin

        Args:
            configuration (Dict): key/value configuration of the plugin

        Returns:
            None
        """
        super.configure(configuration)

    # Plugin Commands
    @cmdfilter
    def duo2fa_filter(self, msg: ErrbotMessage, cmd: str, args: Dict, dry_run: bool)->\
            Tuple(Union(ErrbotMessage, None), Union(str, None), Union(Dict, None)):
        """
        This is a cmd filter, run to filter other plugins. It will check if a cmd requires two factor auth and then
        prompt the user to 2fa as appropriate

        Args:
            msg: the ErrbotMessage objevt
            cmd (str): The command name itself
            args(dict): Args passed to the command
            dry_run (boolean): True when this is a dry run
               Dry-runs are performed by certain commands (such as !help)
               to check whether a user is allowed to perform that command
               if they were to issue it. If dry_run is True then the plugin
               shouldn't actually do anything beyond returning whether the
               command is authorized or not.

        Returns:
            tuple (ErrbotMessage, str, Dict)
        """
        if dry_run:
            return msg, cmd, args

        return msg, cmd, args

    # Helper Functions
    @contextlib.contextmanager
    def stored(self,
               key: str):
        """
        This is a context helper to ease the mutability of the internal plugin storage
        Args:
            key (str): The key you want to retrieve from our internal storage

        """
        value = self[key]
        try:
            yield value
        finally:
            self[key] = value

    def add_command(self,
                    command: str)->None:
        """
        Adds a command to our filter

        Also called by other plugins wanting to add their commands to the filter automatically on activation
        Args:
            command (str): The command to filter

        """
        super.log.debug(f"add_command called from {inspect.stack()[1][3]} with {command}")
        with self.lock:
            with self.stored('cmds') as cmds:
                cmds.add(command)

    def remove_command(self,
                       command: str)->None:
        """
        Adds a command to our filter

        Also called by other plugins wanting to add remove their commands from the filter
        Args:
            command (str): The command to filter

        """
        super.log.debug(f"remove_command called from {inspect.stack()[1][3]} with {command}")
        with self.lock:
            with self.stored('cmds') as cmds:
                del cmds[command]