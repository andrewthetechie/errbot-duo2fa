# errbot-duo2fa
Errbot cmdfilter that enables Duo two-factor authentication for plugin commands

[![Build Status](https://travis-ci.org/andrewthetechie/errbot-duo2fa.svg?branch=master)](https://travis-ci.org/andrewthetechie/errbot-duo2fa)

# Requirements

- errbot-slack: Right now, only the slack backend supports user email lookup
- A [Duo](https://duo.com/) Account with API access

# How it works

This command maintains a list of commands that require 2fa, supplied by other plugins or bot admins. When a command is run, the cmdfilter checks if it is in that list. If the command is in the list, it will start an authorization process against Duo.

# User usage

When a command is set to require 2fa, a user will have to add `--2fa` to the command + a 2fa method. Accepted methods are:

- auto: the recommended or user set method from Duo
- push: Send a push notification to the user's default device
- sms: Send a sms to the user's default device
- phone: Call the user's default device

The bot will then pause while the user completes authentication. If authentication is successful, the command will run as normal. Otherwise, the bot will error and return an error message.

**Note:** Sending just `--2fa` is the same as `--2fa auto`

## Example

	./do stuff --flag thing --2fa
	** User auths via default duo method
	Bot: Did stuff with thing! 

# Configuration

errbot-duo2fa configures itself with environment variables. Set the below variables:

- DUO_API_HOST: api host provided by Duo
- DUO_INT_KEY: integration key provided by Duo
- DUO_SECRET_KEY: secret key provided by Duo

# Usage

Normal usage for this plugin would be to include it as a [dependency for your plugin](http://errbot.io/en/latest/user_guide/plugin_development/dependencies.html#declaring-dependencies) and then in your plugin's activate method, call "add_command".


    from errbot import BotPlugin, botcmd

    class MyPlugin(BotPlugin):

        def activate(self):
                super().activate()  # <-- needs to be *before* get_plugin
                self.get_plugin('Duo2fa').add_command('foo_bar')

                @botcmd
                def foo_bar(self, msg, args):
                        return "Bar" # will only run if --2fa is passed

To remove a command from requiring 2fa:

    from errbot import BotPlugin, botcmd

    class MyPlugin(BotPlugin):

        def activate(self):
                super().activate()  # <-- needs to be *before* get_plugin
				self.get_plugin('Duo2fa').add_command('foo_bar')
				// Do some other stuff and decide to remove the comand
				//
                self.get_plugin('Duo2fa').remove_command('foo_bar')

                @botcmd
                def foo_bar(self, msg, args):
                        return "Bar" # won't require --2fa

## Admin Management from the bot

You can add and remove commands from the chat using the built in `require 2fa` and `remove_2fa` commands. See help for more usage info on these commands.

