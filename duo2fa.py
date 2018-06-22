import contextlib
import inspect
import uuid
import argparse

from functools import lru_cache
from decouple import config
from errbot import BotPlugin
from errbot import botcmd
from errbot import cmdfilter
from errbot.backends.base import Message as ErrbotMessage
from errbot.utils import ValidationException
from duo_client import Auth
from typing import Mapping
from typing import Tuple


class Duo2fa(BotPlugin):
    """
    This implements duo 2fa as a cmdfilter for other plugin commands
    """
    # Plugin Setup Methods
    def __hash__(self):
        """
        Returns a hash of self.cache_id with Duo2fa, needed for LRU caching

        Returns:
            hash
        """
        return hash(str(type(self)) + str(self.cache_id))

    def __init__(self, bot, name=None) -> None:
        """
        Calls super init and adds a few variables of our own
        """
        super().__init__(bot=bot,
                         name=name)
        # cache_id is used to make the object uniquely hashable for lru caching
        self.cache_id = str(uuid.uuid4())

    def activate(self)->None:
        """
        Activate activates our plugin and sets up some things it needs

        Returns:
            None
        """
        super().activate()
        if 'filtered_commands' not in self:
            self['filtered_commands'] = set()

    def configure(self, configuration: Mapping = dict())->None:
        """
        Configure gathers configuration from the user or from the environment and configures the plugin

        Args:
            configuration (Dict): key/value configuration of the plugin

        Returns:
            None
        """
        if 'DUO_API_HOST' not in configuration:
            configuration['DUO_API_HOST'] = config("DUO_API_HOST",
                                                   cast=str)
        if 'DUO_INT_KEY' not in configuration:
            configuration['DUO_INT_KEY'] = config("DUO_INT_KEY",
                                                  cast=str)
        if 'DUO_SECRET_KEY' not in configuration:
            configuration['DUO_SECRET_KEY'] = config("DUO_SECRET_KEY",
                                                     cast=str)

        super().configure(configuration)

    def check_configuration(self, configuration: Mapping)->None:
        """
        Calls the super().check_configuration to do the basic configuration check

        In addition, it checks that the Duo credentials supplied are valid.

        Args:
            configuration (typing.Mapping):

        Returns:
            None

        Raises:
            errbot.utils.ValidationException

        """
        super().check_configuration(configuration)

        # if we're in test mode, just pass and don't try to check on the duo auth
        if self._bot.mode == "test":
            pass

        duo_auth_api = Auth(ikey=configuration['DUO_INT_KEY'],
                            skey=configuration['DUO_SECRET_KEY'],
                            host=configuration['DUO_API_HOST'])
        try:
            duo_auth_api.check()
        except RuntimeError as error:
            self.log.error(f"Unable to connect to Duo api with credentials. {error}")
            raise ValidationException(f"Unable to connect to Duo api with credentials. {error}")

    # Plugin Commands
    @botcmd(admin_only=True)
    def twofa_clear_email_cache(self, msg: ErrbotMessage, args: Mapping) -> None:
        """
        This is an admin only command that will clear the email lookup cache

        Args:
            msg (ErrbotMessage): ErrbotMessage object
            args (Mapping):args

        Returns:
            None
        """
        self.log.debug(f"Clearing email lookup cache @ {msg.frm.user_id} request")
        self.get_user_email.cache_clear()
        self.send(
            msg.to,
            text="Email Lookup Cache cleared",
            in_reply_to=msg
        )
        return

    @botcmd
    def twofa_email_cache_info(self, msg: ErrbotMessage, args: Mapping) -> None:
        """
        This is a command that returns stats about our email lookup cache

        Args:
            msg (ErrbotMessage): ErrbotMessage object
            args (Mapping): args

        Returns:
            None
        """
        cache_info = self.get_user_email.cache_info()
        self.send(
            msg.to,
            text=f"Email Lookup Cache Info\nHits: {cache_info.hits}\n"
                 f"Misses: {cache_info.misses}\n"
                 f"Max Size {cache_info.maxsize}\n"
                 f"Current Size: {cache_info.currsize}",
            in_reply_to=msg
        )
        return

    @cmdfilter
    def duo2fa_filter(self, msg: ErrbotMessage, cmd: str, args: str, dry_run: bool):
        """
        This is a cmd filter, run to filter other plugins. It will check if a cmd requires two factor auth and then
        prompt the user to 2fa as appropriate

        Args:
            msg: the ErrbotMessage objevt
            cmd (str): The command name itself
            args (str): Args passed to the command
            dry_run (boolean): True when this is a dry run
               Dry-runs are performed by certain commands (such as !help)
               to check whether a user is allowed to perform that command
               if they were to issue it. If dry_run is True then the plugin
               shouldn't actually do anything beyond returning whether the
               command is authorized or not.

        Returns:
            Union((ErrbotMessage, str, Dict), (None, None, None))
        """
        if dry_run:
            return msg, cmd, args

        with self.stored('filtered_commands') as filtered_commands:
            # if cmd is not in our filtered cmd list, return immediately so the cmd executes
            if cmd not in filtered_commands:
                return msg, cmd, args

            # at this point, we know this cmd is filtered and we need to 2fa the user
            user_email = self.get_user_email(msg.frm.user_id)
            try:
                user_preauth, message = self.preauth_user(user_email)

                # deny means that duo has denied this email auth.
                if user_preauth == "deny":
                    self.log.debug(f"{user_email} denied by Duo for {cmd}")
                    self.send(
                        msg.to,
                        text=f"You are not authorized to auth to Duo at this time. Please contact your Duo admin."
                             f"\nError message: {message}",
                        in_reply_to=msg
                    )
                    return None, None, None

                # enroll means the user isn't in Duo
                if user_preauth == "enroll":
                    self.log.debug(f"{user_email} is not enrolled in Duo")
                    self.send(
                        msg.to,
                        text=f"You are not enrolled in Duo. Please contact your Duo admin.\nUser Email: {user_email}",
                        in_reply_to=msg
                    )
                    return None, None, None

                # allow means duo has allowed this user without 2fa, maybe based on remember me rules
                if user_preauth == "allow":
                    self.log.debug(f"{user_email} allowed without 2fa by duo for {cmd}")
                    return msg, cmd, args

                # auth means that we can do an auth with this user.
                if user_preauth == "auth":
                    self.log.debug(f"{user_email} needs to 2fa auth via Duo")
                    flag_parser = argparse.ArgumentParser()
                    flag_parser.add_argument("--2fa", action="store_true", dest="twofa")
                    flag_parser.parse_known_args(args.split(" "))
                    if not flag_parser.twofa:
                        self.send(
                            msg.to,
                            text=f"This command requires Duo Two Factor. Rerun this command with --2fa.\n"
                                 f"Your account supports the following 2fa methods: {message}. You can specify your"
                                 f"preferred 2fa method after --2fa like this `--2fa sms`. Just sending --2fa is the"
                                 f"same as --2fa auto",
                            in_reply_to=msg
                        )
                        return None, None, None
                    # ok, we have at least --2fa. Lets check if they sent along any text with it
                    parser = argparse.ArgumentParser()
                    parser.add_argument("--2fa",
                                        action="store",
                                        dest="twofa",
                                        choices=['push', 'auto', 'phone', 'sms'],
                                        default="auto"
                                        )
                    parser.parse_known_args(args.split(" "))
                    twofa_method = parser.twofa
                    twofa_result, message = self.auth_user(user_email, twofa_method)
                    if twofa_result == "deny":
                        self.send(
                            msg.to,
                            text=f"Your Duo 2FA auth failed.\nError message: {message}",
                            in_reply_to=msg
                        )
                        return None, None, None
                    if twofa_result == "allow":
                        return msg, cmd, args

            except RuntimeError as error:
                self.log.debug(f"Error talking to Duo api {error}")
                self.send(
                    msg.to,
                    text=f"Error when talking to the Duo api {error}",
                    in_reply_to=msg
                )
                return None, None, None
        return None, None, None

    # Helper Functions
    @contextlib.contextmanager
    def stored(self, key: str):
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
            with self.stored('filtered_commands') as cmds:
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
            with self.stored('filtered_commands') as cmds:
                del cmds[command]

    @lru_cache(maxsize=256)
    def get_user_email(self, user_id) -> str:
        """
        Turns a Person object into their email. Only works for the slack backend at this time
        Args:
            user_id (str): Id of the user to get the nickname from
        Returns:
            str - Email for the user, or Unsupported Backend
        """
        bot_mode = self._bot.mode
        self.log.debug("get_user_email called")
        # in test mode, let's just return a junk email
        if bot_mode == "test":
            self.log.debug("get_user_email in test mode - returning test@test.com")
            return "test@test.com"

        # ok, slack backend we need to do an API call
        if bot_mode == "slack":
            self.log.debug(f"HelperPlugin::get_user_email in slack mode - querying slack for {user_id} email")
            user_info = self._bot.api_call('users.info', user=user_id)
            if user_info['ok']:
                email = user_info['user']['email']
                self.log.debug(f"get_user_email in slack mode - {user_id}>>{email}")
                return email
            else:
                self.log.error(f"Slack error when looking up email for {user_id}")
                return "Slack Error"
        self.log.debug(f"HelperPlugin::get_user_email in unknown mode - {bot_mode}. Returning Unsupported")
        return "Unsupported Backend"

    @lru_cache(maxsize=8)
    def preauth_user(self, user_email: str) -> Tuple[str, str]:
        """
        Preauths a user against duo
        Args:
            user_email (str): Email of the user to auth

        Returns:
            Tuple(str, str) - preauth status and message
        """
        # TODO: write preauth method using https://duo.com/docs/authapi#/preauth
        return "allow", ""

    def auth_user(self, user_email: str, factor: str = "auto") -> Tuple[str, str]:
        """
        Auths a user against Duo using the chosen auth factor: auto, sms, phone, or push
        Args:
            user_email (str): email of the user to auth
            factor (str): auto, sms, phone, or push

        Returns:
            Tuple(str, str) - Auth result and message
        """
        # TODO: write auth method using https://duo.com/docs/authapi#/auth
        return "allow", ""
