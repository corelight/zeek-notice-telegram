@load policy/protocols/conn/known-hosts

module TelegramDemo;

export {
    redef enum Notice::Type += { NewKnownHost };
    redef Site::local_nets += { 192.168.0.0/16 };
    redef Notice::telegram_token "my-telegram-token";
    redef Notice::telegram_chat_id = "my-chat-id";
    }

event Known::log_known_hosts(rec: Known::HostsInfo)
    {
    NOTICE([$note=NewKnownHost,
            $msg=fmt("New host %s appeared at %D", rec$host, rec$ts),
            $identifier=cat(rec$host)]);
    }

hook Notice::policy(n: Notice::Info)
    {
    if ( n$note == NewKnownHost )
        add n$actions[Notice::ACTION_TELEGRAM];
    }