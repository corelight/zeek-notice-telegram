# zeek-notice-telegram

Zeek package that extends Zeek's Notice Framework to enable sending notices over
[Telegram](https://telegram.org/). The [zeek-notice-slack](https://github.com/pgaulon/zeek-notice-slack)
package was used as inspiration.

## Installation

```
$ zkg install zeek-notice-telegram
```

Otherwise, you can clone this repo and install locally with `zkg`.

## Configuration

In order to use this package, you must [create a Telegram bot](https://core.telegram.org/bots/faq#how-do-i-create-a-bot)
and [identify your user ID](https://www.technobezz.com/how-to-find-user-ids-in-telegram/) or [group chat ID](https://stackoverflow.com/questions/32423837/telegram-bot-how-to-get-a-group-chat-id).
After creating a bot, you will receive a token `$TOKEN` from `@BotFather`. After chatting with `@userinfobot` you will
have your `$CHAT_ID`. To properly configure this package, you will need to:

```
redef Notice::telegram_token = "$TOKEN";
redef Notice::telegram_chat_id = "$CHAT_ID";
```

directly, or modify them using the Configuration Framework. If either of these
are not redefined, reporter warnings will be generated and the Telegram
notifications will not work.

## Usage

In your script, all notices can be sent over Telegram using the following
`hook`:

```
hook Notice::policy(n: Notice::Info)
    {
    add n$actions[Notice::ACTION_TELEGRAM];
    }
```
