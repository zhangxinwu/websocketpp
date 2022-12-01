#include <zlib.h>

//
// Created by xinwu-pc on 2022/11/27.
//
#include <exception>

#ifndef WILIWILI_LIVE_CHAT_API_H
#define WILIWILI_LIVE_CHAT_API_H

#include <thread>

#define ASIO_STANDALONE

#include <websocketpp/config/core_client.hpp>

namespace websocketpp {

    namespace transport {
        namespace test {

            struct socket {

            };

            struct timer {
                void cancel() {}
            };

            template<typename config>
            struct connection : public lib::enable_shared_from_this<connection<config> > {
                /// Type of this connection transport component
                typedef connection<config> type;
                /// Type of a shared pointer to this connection transport component
                typedef lib::shared_ptr<type> ptr;
                /// Type of this transport's access logging policy
                typedef typename config::alog_type alog_type;
                /// Type of this transport's error logging policy
                typedef typename config::elog_type elog_type;

                typedef lib::shared_ptr<timer> timer_ptr;

                explicit connection(bool is_server, const lib::shared_ptr<alog_type> &alog,
                                    const lib::shared_ptr<elog_type> &elog) : m_is_server(is_server), m_alog(alog),
                                                                              m_elog(elog) {
                    std::cout << "connection" << " " << __LINE__ << std::endl;
                    m_alog->write(log::alevel::devel, "iostream con transport constructor");
                }

                void init(init_handler handler) {
                    std::cout << "init" << " " << __LINE__ << std::endl;
                }

                void async_read_at_least(size_t num_bytes, char *buf, size_t len,
                                         read_handler handler) {
                    std::cout << "async_read_at_least" << " " << __LINE__ << std::endl;
                }

                void async_write(const char *buf, size_t len, write_handler handler) {
                    std::cout << "async_write" << " " << __LINE__ << std::endl;
                }

                void async_write(std::vector<buffer> &bufs, write_handler handler) {
                    std::cout << "async_write_vector" << " " << __LINE__ << std::endl;

                }


                void set_handle(connection_hdl hdl) {
                    std::cout << "set_handle" << " " << __LINE__ << std::endl;
                    m_connection_hdl = hdl;
                }

                timer_ptr set_timer(long duration, timer_handler handler) {
                    std::cout << "set_timer" << " " << __LINE__ << std::endl;
                    return timer_ptr();
                }

                std::string get_remote_endpoint() {
                    std::cout << "get_remote_endpoint" << " " << __LINE__ << std::endl;
                    return std::string();
                }

                bool is_secure() const {
                    std::cout << "is_secure" << " " << __LINE__ << std::endl;
                    return false;
                }

                lib::error_code dispatch(dispatch_handler handler) {
                    std::cout << "dispatch" << " " << __LINE__ << std::endl;
                    return lib::error_code();
                }

                void async_shutdown(shutdown_handler handler) {
                    std::cout << "async_shutdown" << " " << __LINE__ << std::endl;
                }

                /// Get a shared pointer to this component
                ptr get_shared() {
                    return type::shared_from_this();
                }

            private:
                bool m_is_server;
                lib::shared_ptr<alog_type> m_alog;
                lib::shared_ptr<elog_type> m_elog;

                connection_hdl m_connection_hdl;
            };

            template<typename config>
            struct endpoint {
                typedef test::connection<config> transport_con_type;
                /// Type of a shared pointer to the transport component of the connections
                /// that this endpoint creates.
                typedef typename transport_con_type::ptr transport_con_ptr;

//                /// Type of this endpoint's concurrency policy
//                typedef typename config::concurrency_type concurrency_type;
                /// Type of this endpoint's error logging policy
                typedef typename config::elog_type elog_type;
                /// Type of this endpoint's access logging policy
                typedef typename config::alog_type alog_type;

                lib::error_code init(transport_con_ptr tcon) {
                    std::cout << "init" << " " << __LINE__ << std::endl;
                    m_is_secure = tcon->is_secure();
                    return lib::error_code();
                }

                bool is_secure() const {
                    std::cout << "is_secure" << " " << __LINE__ << std::endl;
                    return m_is_secure;
                }

                void async_connect(transport_con_ptr tcon, uri_ptr location,
                                   connect_handler handler) {
                    std::cout << "async_connect" << " " << __LINE__ << std::endl;

                }

                void init_logging(const lib::shared_ptr<alog_type> &a, const lib::shared_ptr<elog_type> &e) {
                    std::cout << "init_logging" << " " << __LINE__ << std::endl;
                    m_alog = a;
                    m_elog = e;
                }
            private:
                lib::shared_ptr<alog_type> m_alog;
                lib::shared_ptr<elog_type> m_elog;
                bool m_is_secure;
            };
        }
    }

    namespace config {

/// Client config with asio transport and TLS disabled
        struct test_client : public core_client {
            typedef test_client type;
            typedef core_client base;

            typedef base::concurrency_type concurrency_type;

            typedef base::request_type request_type;
            typedef base::response_type response_type;

            typedef base::message_type message_type;
            typedef base::con_msg_manager_type con_msg_manager_type;
            typedef base::endpoint_msg_manager_type endpoint_msg_manager_type;

            typedef base::alog_type alog_type;
            typedef base::elog_type elog_type;

            typedef base::rng_type rng_type;

            struct transport_config : public base::transport_config {
                typedef type::concurrency_type concurrency_type;
                typedef type::alog_type alog_type;
                typedef type::elog_type elog_type;
                typedef type::request_type request_type;
                typedef type::response_type response_type;
                typedef websocketpp::transport::test::socket
                        socket_type;
            };

            typedef websocketpp::transport::test::endpoint<transport_config>
                    transport_type;
        };

    } // namespace config
} // namespace websocketpp

#include <websocketpp/client.hpp>

namespace brls {
    namespace Logger {
#define LL(level) \
    void level(std::string arg) { std::cout << #level << " " << arg << std::endl; }

        LL(error);

        LL(warning);

        LL(info);

        LL(debug);

        LL(verbose);

        // void error(std::string args){std::cout << "error" << arg << std::endl;}
        // void warning(std::string args){}
        // void info(std::string args){}
        // void debug(std::string args){}
        // void verbose(std::string args){}
    }
}
namespace bilibili {

    namespace Api {
        static std::string LiveChatUrl = "ws://broadcastlv.chat.bilibili.com:2244/sub";
    }

    typedef websocketpp::client<websocketpp::config::test_client> client;

    typedef std::function<void(const std::string &)> livechat_callback_func;

    struct WsHeader {
        uint32_t len = 0;
        uint16_t headerlen = sizeof(WsHeader);
        uint16_t ver = 1;
        uint32_t op = 1;
        uint32_t seq = 1;

        void htonx() {
            len = htonl(len);
            headerlen = htons(headerlen);
            ver = htons(ver);
            op = htonl(op);
            seq = htonl(seq);
        }

        void ntohx() {
            len = ntohl(len);
            headerlen = ntohs(headerlen);
            ver = ntohs(ver);
            op = ntohl(op);
            seq = ntohl(seq);
        }
    };

    enum LiveChatOpcode {
        // 客户端发送心跳值
        WS_OP_HEARTBEAT = 2,
        // 服务端返回心跳值
        WS_OP_HEARTBEAT_REPLY = 3,
        // 返回消息
        WS_OP_MESSAGE = 5,
        // 用户授权加入房间
        WS_OP_USER_AUTHENTICATION = 7,
        // 建立连接成功，客户端接收到此信息时需要返回一个心跳包
        WS_OP_CONNECT_SUCCESS = 8,
    };

    enum LiveChatVer {
        WS_HEADER_DEFAULT_VERSION = 1,
        // deflate 压缩版本
        WS_BODY_PROTOCOL_VERSION_DEFLATE = 2,
    };

    static const int HEART_TIMER_SEC = 30;
    static const int DATA_SIZE_MAX = 40960;

    class LiveChat {
    public:
        int start(int roomid, livechat_callback_func callback);

        ~LiveChat();

    private:
        void HeartTimeout(const websocketpp::lib::error_code &ec);

        void on_open(websocketpp::connection_hdl hdl);

        void on_message(websocketpp::connection_hdl, client::message_ptr msg);

        void on_message(websocketpp::connection_hdl, const std::string &data);

        std::string get_msg(const std::string &s, LiveChatOpcode op);

    public:
        int roomid;
        livechat_callback_func callback;
        client c;
        websocketpp::connection_hdl hdl;
        // std::shared_ptr<asio::high_resolution_timer> t;
        std::shared_ptr<std::thread> th;
    };

} // namespace bilibili
#endif // WILIWILI_LIVE_CHAT_API_H

namespace bilibili {

    std::string LiveChat::get_msg(const std::string &s, LiveChatOpcode op) {
        WsHeader header;
        int len = sizeof(WsHeader) + s.size();
        header.len = len;
        header.op = op;
        header.htonx();
        char data[len];
        memcpy(data, &header, sizeof(header));
        memcpy(data + sizeof(header), s.c_str(), s.size());
        return {data, len};
    }

    void LiveChat::on_message(websocketpp::connection_hdl hdl,
                              client::message_ptr msg) {
        on_message(hdl, msg->get_payload());
    }

    void LiveChat::on_message(websocketpp::connection_hdl hdl,
                              const std::string &data) {
        int total = data.size();
        int begin = 0;
        brls::Logger::debug("on _message total " + std::to_string(total));
        WsHeader header;
        while (begin < total && begin + sizeof(WsHeader) <= total) {
            memcpy(&header, data.data() + begin, sizeof(WsHeader));
            header.ntohx();
            // brls::Logger::debug("len " + std::to_string(header.len))

            if (header.len < sizeof(WsHeader) || header.len > total - begin ||
                header.len < header.headerlen) {
                brls::Logger::verbose("LiveChat on_message header.len is invalid." + std::to_string(header.len));
                break;
            }
            if (header.op == LiveChatOpcode::WS_OP_CONNECT_SUCCESS) {
                HeartTimeout(websocketpp::lib::error_code());
            } else if (header.op == LiveChatOpcode::WS_OP_MESSAGE) {
                if (header.ver == LiveChatVer::WS_BODY_PROTOCOL_VERSION_DEFLATE) {
                    static char in[DATA_SIZE_MAX];
                    static char ud[DATA_SIZE_MAX];
                    if (header.len - header.headerlen > DATA_SIZE_MAX) {
                        // brls::Logger::warning(
                        //    "LiveChat on_message get_data too big");
                        continue;
                    }
                    memset(ud, 0, sizeof(ud));
                    z_stream strm;
                    memset(&strm, 0, sizeof(z_stream));
                    int ret = inflateInit2(&strm, 15 | 32);
                    if (ret) {
                        brls::Logger::warning(
                                "LiveChat on_message zlib strm init error " +
                                std::to_string(ret));
                        continue;
                    }
                    memcpy(in, data.data() + begin + header.headerlen,
                           header.len - header.headerlen);
                    strm.next_in = reinterpret_cast<Bytef *>(in);
                    strm.avail_in = header.len - header.headerlen;
                    strm.next_out = reinterpret_cast<Bytef *>(ud);
                    strm.avail_out = sizeof(ud);
                    ret = inflate(&strm, Z_NO_FLUSH);
                    if (Z_OK == ret || Z_STREAM_END == ret) {
                        brls::Logger::debug("zlib ret " + std::to_string(ret));
                        on_message(hdl, std::string(ud, strm.total_out));
                    }
                    inflateEnd(&strm);
                } else {
                    callback(std::string(data.data() + begin + header.headerlen,
                                         header.len - header.headerlen));
                }
            }
            begin += header.len;
        }
    }

    void LiveChat::on_open(websocketpp::connection_hdl hdl) {
        websocketpp::lib::error_code ec;
        std::string j("{\"uid\": 1,\"roomid\": " + std::to_string(roomid) +
                      ",\"protover\": 1,\"platform\": "
                      "\"web\",\"clientver\": \"1.4.0\"}");
        std::string data = get_msg(j, LiveChatOpcode::WS_OP_USER_AUTHENTICATION);
        c.send(hdl, data, websocketpp::frame::opcode::value::binary, ec);
        if (ec) {
            brls::Logger::error("LiveChat on_open " + ec.message());
        }
    }

    //定时器回调函数
    void LiveChat::HeartTimeout(const websocketpp::lib::error_code &ec) {
        if (ec) {
            brls::Logger::error("timer is cancel " + ec.message());
            return;
        }
        brls::Logger::info("HeartTimeout");

        websocketpp::lib::error_code ecc;
        c.send(hdl, get_msg("", LiveChatOpcode::WS_OP_HEARTBEAT),
               websocketpp::frame::opcode::value::binary, ecc);
        if (ecc) {
            brls::Logger::error("could not create connection because: " +
                                ec.message());
        }
        // if (!t)
        // {
        //     t = std::make_shared<asio::high_resolution_timer>(
        //         c.get_io_service(), std::chrono::seconds(0));
        // }
        // t->expires_at(t->expires_at() +
        //               std::chrono::seconds(HEART_TIMER_SEC));
        // t->async_wait([this](const websocketpp::lib::error_code &err)
        //               { this->HeartTimeout(err); });
    }

    int LiveChat::start(int roomid, livechat_callback_func callback) {
        if (sizeof(WsHeader) != 0x10)
            return -1;
        try {
            this->roomid = roomid;
            this->callback = callback;
            c.set_access_channels(websocketpp::log::alevel::devel);
//            c.clear_access_channels(websocketpp::log::alevel::all);
            c.set_error_channels(websocketpp::log::elevel::devel);

            // c.init_asio();

            // Register our message handler
            c.set_message_handler(
                    [this](auto h, auto m) { return this->on_message(h, m); });
            c.set_open_handler([this](auto h) { return this->on_open(h); });
            // c.set_tls_init_handler([](websocketpp::connection_hdl)
            //                        { return websocketpp::lib::make_shared<asio::ssl::context>(
            //                              asio::ssl::context::tlsv13_client); });
//            c.set_write_handler(
//                [](websocketpp::connection_hdl hdl, char const *s, size_t d)
//                {
//                    for (int i = 0; i < d; i++)
//                        printf("%02x ", s[i]);
//                    printf("\n");
//                    return websocketpp::lib::error_code();
//                });
            websocketpp::lib::error_code ec;
            client::connection_ptr con = c.get_connection(Api::LiveChatUrl, ec);
            if (ec) {
                brls::Logger::error(
                        "LiveChat could not create connection because: " +
                        ec.message());
                return -1;
            }
            hdl = con->get_handle();

            c.connect(con);
            con->start();
            HeartTimeout(ec);

            // th = std::make_shared<std::thread>([this]
            //                                    { c.run(); });
        }
        catch (websocketpp::exception const &e) {
            brls::Logger::error("LiveChat start error, roomid " +
                                std::to_string(roomid) + " " + e.what());
            return -1;
        }
        return 0;
    }

    LiveChat::~LiveChat() {
        // if (t)
        //     t->cancel();
        callback = nullptr;
        c.close(hdl, 0, "");
        if (th)
            th->join();
        std::cout << "finised!!!!!" << std::endl;
    }

}; // namespace bilibili

int main() {
    // std::cin >> bilibili::Api::LiveChatUrl;
    try {
        bilibili::LiveChat l;
        l.start(7685334,
                [](std::string s) { std::cout << ">| " << std::to_string(s.size() + 16) << " " << s << std::endl; });
        char c = '\0';
        while (scanf("%c", &c) != EOF && c != 'c');
    }
    catch (websocketpp::exception &e) {
        std::cout << e.what() << std::endl;
    }
    char c = '\0';
    while (scanf("%c", &c) != EOF && c != 'c');
}

// ws://broadcastlv.chat.bilibili.com:7170/sub
// ws://broadcastlv.chat.bilibili.com:2244/sub

// ws://broadcastlv.chat.bilibili.com:2244/sub
