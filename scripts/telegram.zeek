##! This provides an interface for sending Notices to a Telegram user or group
##! chat.

@load base/frameworks/notice
@load base/utils/active-http

module Notice;

export {
    redef enum Action += {
        ACTION_TELEGRAM,
    };

    const telegram_endpoint = "https://api.telegram.org";
    # These must be redef'd to work.
    # See https://core.telegram.org/bots/faq#how-do-i-create-a-bot for details
    option telegram_token = "REDEF-TOKEN";
    option telegram_chat_id = "REDEF-ID";

    global telegram_payload: function(n: Notice::Info): string;
    global telegram_send_notice: function(text: string);
}

function telegram_send_notice(text: string)
    {
    if (telegram_token == "REDEF-TOKEN" || telegram_chat_id == "REDEF-ID")
        {
        Reporter::warning("Notice::telegram_token and Notice::telegram_chat_id must be redef'd to use Notice::ACTION_TELEGRAM");
        return;
        }
    local url = cat_sep("/", "", telegram_endpoint, cat("bot", telegram_token), "sendMessage");
    local request: ActiveHTTP::Request = ActiveHTTP::Request(
        $url=url,
        $method="POST",
        $client_data=fmt("chat_id=%s&text=%s", telegram_chat_id, text)
    );

    when ( local result = ActiveHTTP::request(request) )
        {
        if ( result$code != 200 )
            Reporter::warning(fmt("Telegram notice failed (%d): %s", result$code, result$body));
        }
    }

function telegram_payload(n: Notice::Info): string
    {
    local text = fmt("%s: %s", n$note, n$msg);
    if ( n?$sub )
        {
        text = string_cat(text,
            fmt(" (%s)", n$sub));
        }
    if ( n?$id )
        {
        text = string_cat(text, ", Connection: ",
            fmt("%s", n$id$orig_h), ":", fmt("%d", n$id$orig_p), " -> ",
            fmt("%s", n$id$resp_h), ":", fmt("%d", n$id$resp_p));
        if ( n?$uid )
            text = string_cat(text, ", Connection uid: ", n$uid);
        }
    else if ( n?$src )
        text = string_cat(text, fmt(", Source: %s", n$src));

    return text;
    }

hook notice(n: Notice::Info)
    {
        if ( ACTION_TELEGRAM in n$actions )
            telegram_send_notice(telegram_payload(n));
    }
