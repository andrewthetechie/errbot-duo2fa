import hashlib
import uuid

pytest_plugins = ["errbot.backends.test"]

extra_plugin_dir = "."


class MockDuoAuthClient(object):
    def __init__(self):
        self.preauth_json = dict()
        self.auth_json = dict()
        self.preauth_raise_error = False
        self.auth_raise_error = False
        self.preauth_call_count = 0
        self.auth_call_count = 0

    def preauth(self, username):
        self.preauth_call_count += 1
        if self.preauth_raise_error:
            raise RuntimeError("Error raised")
        return self.preauth_json

    def auth(self, username, factor):
        self.auth_call_count += 1
        if self.auth_raise_error:
            raise RuntimeError("Error raised")
        return self.auth_json


# Tests for setup methods
def test_hash(testbot):
    """
    tests __hash__

    """
    plugin = testbot.bot.plugin_manager.get_plugin_obj_by_name("Duo2fa")
    our_uuid = str(uuid.uuid4())
    plugin.cache_id = our_uuid

    assert hash(hashlib.md5(f"Duo2fa-{plugin.cache_id}".encode('utf-8')).hexdigest()) == plugin.__hash__()


# Tests for helper methods
def test_stored(testbot):
    """
    Tests stored

    """
    plugin = testbot.bot.plugin_manager.get_plugin_obj_by_name("Duo2fa")

    plugin.add_command("test")

    with plugin.stored("filtered_commands") as filtered_cmds:
        assert "test" in filtered_cmds
        filtered_cmds.add("test2")

    assert "test2" in plugin['filtered_commands']


def test_add_command(testbot):
    """
    Tests add_command

    """
    plugin = testbot.bot.plugin_manager.get_plugin_obj_by_name("Duo2fa")

    assert plugin['filtered_commands'] == set()

    plugin.add_command("require_2fa")
    assert "require_2fa" in plugin['filtered_commands']


def test_remove_command(testbot):
    """
    Tests remove_command

    """
    plugin = testbot.bot.plugin_manager.get_plugin_obj_by_name("Duo2fa")

    plugin.add_command("require_2fa")
    assert "require_2fa" in plugin['filtered_commands']

    plugin.remove_command("require_2fa")
    assert "require_2fa" not in plugin['filtered_commands']


def test_get_user_email(testbot):
    """
    test get_user_email

    """
    # This test is a bit silly as in test mode, this method returns a static value.
    # However, we also test the lru caching here
    plugin = testbot.bot.plugin_manager.get_plugin_obj_by_name("Duo2fa")

    testbot.push_message("!twofa email cache info")
    msg = testbot.pop_message()
    assert msg == "Email Lookup Cache Info\nHits: 0\nMisses: 0\n" \
                  "Max Size 256\nCurrent Size: 0"

    email = plugin.get_user_email(user_id="123456")
    assert email == "test@test.com"

    testbot.push_message("!twofa email cache info")
    msg = testbot.pop_message()
    assert msg == "Email Lookup Cache Info\nHits: 0\nMisses: 1\n" \
                  "Max Size 256\nCurrent Size: 1"

    email = plugin.get_user_email(user_id="123456")
    assert email == "test@test.com"

    testbot.push_message("!twofa email cache info")
    msg = testbot.pop_message()
    assert msg == "Email Lookup Cache Info\nHits: 1\nMisses: 1\n" \
                  "Max Size 256\nCurrent Size: 1"

    testbot.push_message("!twofa email cache clear")
    msg = testbot.pop_message()
    assert msg == "Email Lookup Cache cleared"

    testbot.push_message("!twofa email cache info")
    msg = testbot.pop_message()
    assert msg == "Email Lookup Cache Info\nHits: 0\nMisses: 0\n" \
                  "Max Size 256\nCurrent Size: 0"


def test_preauth_user(testbot):
    """
    tests preauth_user

    Returns:

    """
    plugin = testbot.bot.plugin_manager.get_plugin_obj_by_name("Duo2fa")
    # monkeypatch the duo auth client
    plugin.duo_auth_api = MockDuoAuthClient()
    plugin.duo_auth_api.preauth_json = {"result": "pass", "status_msg": "pass"}

    result, message = plugin.preauth_user("test@test.com")

    assert result == "pass"
    assert message == "pass"
    assert plugin.duo_auth_api.preauth_call_count == 1

    # test caching
    result, message = plugin.preauth_user("test@test.com")
    assert result == "pass"
    assert message == "pass"
    assert plugin.duo_auth_api.preauth_call_count == 1


def test_auth_user(testbot):
    """
    tests auth_user

    """
    plugin = testbot.bot.plugin_manager.get_plugin_obj_by_name("Duo2fa")
    # monkeypatch the duo auth client
    plugin.duo_auth_api = MockDuoAuthClient()
    plugin.duo_auth_api.auth_json = {"result": "pass", "status_msg": "pass"}

    result, message = plugin.auth_user("test@test.com")

    assert result == "pass"
    assert message == "pass"


def test_parse_2fa_args(testbot):
    """
    tests parse_2fa_args

    """
    plugin = testbot.bot.plugin_manager.get_plugin_obj_by_name("Duo2fa")

    # test no 2fa
    test_args = "stuff"
    method, args = plugin.parse_2fa_args(test_args)
    assert method is None
    assert args == "stuff"

    # test --2fa on end
    test_args = "stuff --2fa"
    method, args = plugin.parse_2fa_args(test_args)
    assert method == "auto"
    assert args == "stuff"

    # test --2fa push
    test_args = "stuff --2fa push"
    method, args = plugin.parse_2fa_args(test_args)
    assert method == "push"
    assert args == "stuff"

    # test --2fa SMS
    test_args = "stuff --2fa SMS"
    method, args = plugin.parse_2fa_args(test_args)
    assert method == "sms"
    assert args == "stuff"

    # test --2fa push --otherflag
    test_args = "stuff --2fa push --otherflag"
    method, args = plugin.parse_2fa_args(test_args)
    assert method == "push"
    assert args == "stuff --otherflag"

    # test --2fa --otherflag stuff
    test_args = "stuff --2fa --otherflag stuff"
    method, args = plugin.parse_2fa_args(test_args)
    assert method == "auto"
    assert args == "stuff --otherflag stuff"

    # test --2fa --otherflag push
    test_args = "stuff --2fa --otherflag push"
    method, args = plugin.parse_2fa_args(test_args)
    assert method == "auto"
    assert args == "stuff --otherflag push"


# Tests for botcmds
def test_require_2fa(testbot):
    """
    Tests require_2fa

    """
    plugin = testbot.bot.plugin_manager.get_plugin_obj_by_name("Duo2fa")

    assert plugin['filtered_commands'] == set()

    testbot.push_message("!require 2fa test_command")
    msg = testbot.pop_message()
    assert msg == "test_command not in our bot's command list. Make sure you are adding the command based on the " \
                  "python function name for the plugin"

    testbot.push_message("!require 2fa echo")
    msg = testbot.pop_message()
    assert msg == "echo now requires 2fa"

    testbot.push_message("!require 2fa echo")
    msg = testbot.pop_message()
    assert msg == "echo already requires 2fa"


def test_remove_2fa(testbot):
    """
    Tests remove_2fa

    """
    plugin = testbot.bot.plugin_manager.get_plugin_obj_by_name("Duo2fa")

    assert plugin['filtered_commands'] == set()

    testbot.push_message("!remove 2fa test_command")
    msg = testbot.pop_message()
    assert msg == "test_command does not require 2fa"

    plugin.add_command("echo")
    testbot.push_message("!remove 2fa echo")
    msg = testbot.pop_message()
    assert msg == "echo no longer requires 2fa"


# Test the cmdfilter
def test_duo2fa_filter(testbot):
    """
    Tests our cmdfilter

    """
    # TODO: WRite these ttests. Need to make the mocker take different repsonses for auth and preauth, so we can hit all the states






